Implements a login portal for an nginx based SSO auth using Discord.

## Setup

### Pre-requisites

Assuming you have the following two hostnames:
-    `$LOGIN_HOSTNAME`: the hostname on which your OAuth callback will be
     registered.
-    `$CLIENT_HOSTNAME`: any hostname that needs to be protected by the
     login portal.

Make sure the following pre-requisites are performed:
-    Hostnames are served through HTTPS (e.g. [using Let's
     Encrypt][lets_encrypt_guide]).
-    Register a Discord application on the [developer portal][discord-devp].
-    Register your Discord OAuth2 as docker secrets:
     -   `echo "112233..." | docker secret create discord_client_id -`
     -   `echo "332211..." | docker secret create discord_client_secret -`

### Nginx setup

Create a simple redirection to the portal (exposed by default on port 3322).

#### Login handler setup

<details>

<summary>`/etc/nginx/sites-available/$LOGIN_HOSTNAME.conf`</summary>

```nginx
server {
    listen 443 ssl;
    server_name $LOGIN_HOSTNAME;

    # ...

    location / {
        proxy_pass http://localhost:3322;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
</details>


Create a `sso_login.conf` snippet that will be included in every client
nginx configuration.

<details>

<summary>`/etc/nginx/snippets/sso_login.conf`</summary>

```nginx
# Provide route handlers to support SSO using the auth JS module.
#
# Usage:
# server {
#     listen 443 ssl;
#     ...
#     include /etc/nginx/snippets/sso_login.conf;
#
#     # For routes you want to protect using SSO auth:
#     location / {
#         auth_request /__auth_internal;
#         error_page 401 = @error401;
#
#         ...
#     }
#     # Other route may not implement auth.
#     location /static {
#         ...
#     }
# }

# Public endpoint setting the auth cookie.
#
# This is the redirection point from the login_service
# once the Discord OAuth process has been completed.
location = /_auth {
    js_content auth.generate;
}

# Internal location handling the authentication check.
#
# Not exposed to clients, only used by route implementation
# to perform the auth check.
location = /__auth_internal {
    internal;
    js_content auth.validate;
}

# Internal location handling the authentication token validation
#
# Not exposed to clients, only used by the auth module to
# verify the validity of the token when /_auth is called.
location = /__auth_validate {
    internal;
    proxy_pass https://login_service/validate$is_args$args;
    # Set headers for the upstream.
    proxy_set_header Host "$LOGIN_HOSTNAME";
    proxy_set_header X-Real-Ip $remote_addr;
}

# Redirects to $LOGIN_HOSTNAME on 401 errors.
#
# Routes to the auth service.
location @error401 {
    return 302 https://$LOGIN_HOSTNAME/login?host=$host&back=$request_uri;
}
```
</details>

Create the auth JavaScript internal handlers.

<details>

<summary>`/etc/nginx/scripts/auth.js`</summary>

```js
import crypto from 'crypto';

function validate(r) {
    const secret = r.variables.auth_secret;
    const cookieName = 'auth_token';
    const token = r.variables[`cookie_${cookieName}`];

    if (!token) {
        r.error('Auth token cookie not found.');
        r.return(401, 'Missing auth cookie');
        return;
    }

    const parts = token.split('.');
    if (parts.length !== 2) {
        r.error(`Invalid token format for cookie: ${token}`);
        r.return(401, 'Invalid token format');
        return;
    }

    const payloadB64 = parts[0];
    const signatureProvided = parts[1];

    // Validate the signature
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(payloadB64);
    const signatureExpected = hmac.digest('hex');
    if (signatureProvided !== signatureExpected) {
        r.error('Token signature mismatch');
        r.return(401, 'Invalid signature');
        return;
    }

    // Decode payload and check expiration
    try {
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        const now = Math.floor(Date.now() / 1000);

        if (payload.exp < now) {
            r.warn(`Token expired at ${new Date(payload.exp * 1000).toISOString()}`);
            r.return(401, 'Token expired');
            return;
        }

        r.headersOut['X-Auth-User'] = payload.sub;
        r.return(200); // Success
    } catch (e) {
        r.error(`Token payload decoding error: ${e.message}`);
        r.return(401, 'Invalid payload');
    }
}

async function generate(r) {
    const backUrl = r.args.back || '/';
    const token = r.args.token;
    const host = r.variables.host;
    if (!token) {
        r.error('Missing token for auth cookie generator.');
        r.return(401, 'Missing token');
        return;
    }

    // Verify the token is valid.
    const validateArgs = `token=${encodeURIComponent(token)}&host=${encodeURIComponent(host)}`;
    const reply = await r.subrequest('/__auth_validate', {args: validateArgs});
    if (reply.status !== 200) {
        r.error(`Token validation failed with status ${reply.status}`);
        r.return(401, 'Token validation failed');
        return;
    }


    // Generate cookie content
    const secret = r.variables.auth_secret;
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        sub: token,
        iat: now,
        exp: now + 86400, // 24 hours
    };

    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');

    // Generate signature
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(payloadB64);
    const signature = hmac.digest('hex');

    // Write the cookie
    const cookieValue = `${payloadB64}.${signature}`;
    const cookieOpts = 'Path=/; HttpOnly; Secure; Max-Age=86400';
    r.headersOut['Set-Cookie'] = `auth_token=${cookieValue}; ${cookieOpts}`;
    r.return(302, backUrl);
}

export default { validate, generate };
```

</details>

Validate configuration and reload nginx.

```
sudo nginx -t
sudo systemctl reload nginx
```

#### Client setup

Create a nginx configuration for your website using `auth_request`
module:

<details>

<summary>`/etc/nginx/sites-available/$CLIENT_HOSTNAME.conf`</summary>

```nginx
server {
    listen 443 ssl; # managed by Certbot
    server_name $CLIENT_HOSTNAME;

    # ...

    include /etc/nginx/snippets/sso_login.conf;

    location / {
        # Add the auth request and error page handlers.
        auth_request /__auth_internal;
        error_page 401 = @error401;

        proxy_pass http://localhost:8000; # Example, to be replaced with actual website.
        # ...
    }
}
```
</details>

[lets_encrypt_guide]: https://archive.esc.sh/blog/lets-encrypt-and-nginx-definitive-guide/
[discord-devp]: https://discord.com/developers/applications
