import os
import jwt
import time
import argparse
import tomli
from urllib.parse import quote
from flask import Flask, request, redirect
import requests
from cachelib import SimpleCache

app = Flask(__name__)
cache = SimpleCache()
config = {}

def get_secret(secret_name, default=None):
    try:
        with open(f'/run/secrets/{secret_name}', 'r') as secret_file:
            return secret_file.read().strip()
    except IOError:
        return os.getenv(secret_name.upper(), default)

def load_config(config_path=None):
    if not config_path:
        config_path = os.getenv("LOGIN_PORTAL_CONFIG")
    if not config_path:
        raise ValueError("LOGIN_PORTAL_CONFIG environment variable not set")
    with open(config_path, "rb") as f:
        config.update(tomli.load(f))

DISCORD_CLIENT_ID = get_secret("discord_client_id")
DISCORD_CLIENT_SECRET = get_secret("discord_client_secret")
DISCORD_API_BASE_URL = "https://discord.com/api"

def get_discord_redirect_uri():
    return f"https://{config['server']['host']}/callback"

@app.route("/login")
def login():
    host = request.args.get("host")
    if host not in config.get("hosts", {}):
        return "Invalid host", 400
    back = request.args.get("back")
    state = f"{host}|{back}"
    redirect_uri = quote(get_discord_redirect_uri(), safe='')
    return redirect(
        f"{DISCORD_API_BASE_URL}/oauth2/authorize?client_id={DISCORD_CLIENT_ID}&redirect_uri={redirect_uri}&response_type=code&scope=identify&state={state}"
    )

@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    host, back = state.split("|")
    if host not in config.get("hosts", {}):
        return "Invalid host", 400

    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": get_discord_redirect_uri(),
        "scope": "identify",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(f"{DISCORD_API_BASE_URL}/oauth2/token", data=data, headers=headers)
    token_data = response.json()
    access_token = token_data["access_token"]

    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{DISCORD_API_BASE_URL}/users/@me", headers=headers)
    user = response.json()

    token = jwt.encode(
        {"user": user, "access_token": access_token, "host": host, "exp": time.time() + 3600},
        DISCORD_CLIENT_SECRET,
        algorithm="HS256",
    )

    return redirect(f"https://{host}/_auth?token={token}&path={back}")

@app.route("/validate")
def validate():
    token = request.args.get("token")
    host = request.args.get("host")

    cache_key = f"{token}:{host}"
    cached_result = cache.get(cache_key)
    if cached_result:
        return cached_result, 200

    try:
        decoded_token = jwt.decode(token, DISCORD_CLIENT_SECRET, algorithms=["HS256"])
        if decoded_token.get("host") != host:
            return "Invalid host for this token", 401

        cache.set(cache_key, "OK", timeout=600)
        return "OK", 200
    except jwt.ExpiredSignatureError:
        return "Expired token", 401
    except jwt.InvalidTokenError:
        return "Invalid token", 401

@app.route("/logout")
def logout():
    token = request.args.get("token")
    if token:
        try:
            decoded_token = jwt.decode(token, DISCORD_CLIENT_SECRET, algorithms=["HS256"], leeway=10)
            access_token = decoded_token.get("access_token")
            if access_token:
                data = {
                    'token': access_token,
                    'client_id': DISCORD_CLIENT_ID,
                    'client_secret': DISCORD_CLIENT_SECRET,
                }
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                requests.post(f'{DISCORD_API_BASE_URL}/oauth2/token/revoke', data=data, headers=headers)
        except jwt.InvalidTokenError:
            pass
        finally:
            try:
                decoded_token = jwt.decode(token, DISCORD_CLIENT_SECRET, algorithms=["HS256"], options={"verify_signature": False, "verify_exp": False})
                host = decoded_token.get("host")
                if host:
                    cache_key = f"{token}:{host}"
                    cache.delete(cache_key)
            except jwt.InvalidTokenError:
                pass

    return "Logged out", 200

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    load_config(args.config)
    app.run(port=config["server"]["port"])
else:
    load_config()
