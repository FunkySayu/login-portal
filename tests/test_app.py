import unittest
from unittest.mock import patch, MagicMock
import jwt
import time
import tempfile
import os
from src.app import app, cache, load_config

class TestApp(unittest.TestCase):

    def setUp(self):
        app.testing = True
        self.app = app.test_client()
        self.client_id_patcher = patch('src.app.DISCORD_CLIENT_ID', 'test_id')
        self.client_secret_patcher = patch('src.app.DISCORD_CLIENT_SECRET', 'test_secret')
        self.env_patcher = patch.dict(os.environ, {"LOGIN_PORTAL_CONFIG": ""}, clear=True)

        self.mock_client_id = self.client_id_patcher.start()
        self.mock_client_secret = self.client_secret_patcher.start()
        self.mock_env = self.env_patcher.start()

        self.config_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.config_file.write("""
[server]
host = "login.example.com"

[hosts]
"example.com" = {}
"test.com" = {}
""")
        self.config_file.close()
        load_config(self.config_file.name)

        # Clear the cache before each test
        cache.clear()


    def tearDown(self):
        self.client_id_patcher.stop()
        self.client_secret_patcher.stop()
        self.env_patcher.stop()
        os.unlink(self.config_file.name)

    def test_login_valid_host(self):
        response = self.app.get('/login?host=example.com&back=/foo')
        self.assertEqual(response.status_code, 302)
        self.assertTrue('client_id=test_id' in response.location)
        self.assertTrue('redirect_uri=https%3A%2F%2Flogin.example.com%2Fcallback' in response.location)
        self.assertTrue(response.location.startswith('https://discord.com/api/oauth2/authorize'))

    def test_login_invalid_host(self):
        response = self.app.get('/login?host=invalid.com&back=/foo')
        self.assertEqual(response.status_code, 400)

    @patch('src.app.requests.post')
    @patch('src.app.requests.get')
    def test_callback_valid_host(self, mock_get, mock_post):
        mock_post.return_value = MagicMock(json=lambda: {'access_token': 'test_token'})
        mock_get.return_value = MagicMock(json=lambda: {'id': '123', 'username': 'testuser'})
        response = self.app.get('/callback?code=test_code&state=example.com|/foo')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.startswith('https://example.com/_auth?token='))
        token = response.location.split('token=')[1].split('&')[0]
        decoded_token = jwt.decode(token, 'test_secret', algorithms=["HS256"])
        self.assertEqual(decoded_token['user']['id'], '123')
        self.assertEqual(decoded_token['access_token'], 'test_token')
        self.assertEqual(decoded_token['host'], 'example.com')


    @patch('src.app.requests.post')
    @patch('src.app.requests.get')
    def test_callback_invalid_host(self, mock_get, mock_post):
        mock_post.return_value = MagicMock(json=lambda: {'access_token': 'test_token'})
        mock_get.return_value = MagicMock(json=lambda: {'id': '123', 'username': 'testuser'})
        response = self.app.get('/callback?code=test_code&state=invalid.com|/foo')
        self.assertEqual(response.status_code, 400)


    def test_validate_valid_token(self):
        token = jwt.encode(
            {"user": {"id": "123"}, "host": "example.com", "exp": time.time() + 3600},
            'test_secret',
            algorithm="HS256",
        )
        response = self.app.get(f'/validate?token={token}&host=example.com')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'OK')
        self.assertEqual(cache.get(f"{token}:example.com"), "OK")


    def test_validate_valid_token_cached(self):
        token = "cached_token"
        cache.set(f"{token}:example.com", "OK")
        response = self.app.get(f'/validate?token={token}&host=example.com')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'OK')


    def test_validate_invalid_host_for_token(self):
        token = jwt.encode(
            {"user": {"id": "123"}, "host": "example.com", "exp": time.time() + 3600},
            'test_secret',
            algorithm="HS256",
        )
        response = self.app.get(f'/validate?token={token}&host=another.com')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, b'Invalid host for this token')

    def test_validate_expired_token(self):
        token = jwt.encode(
            {"user": {"id": "123"}, "host": "example.com", "exp": time.time() - 3600},
            'test_secret',
            algorithm="HS256",
        )
        response = self.app.get(f'/validate?token={token}&host=example.com')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, b'Expired token')

    def test_validate_invalid_token(self):
        response = self.app.get('/validate?token=invalid_token&host=example.com')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, b'Invalid token')

    @patch('src.app.requests.post')
    def test_logout(self, mock_post):
        token = jwt.encode(
            {"user": {"id": "123"}, "access_token": "test_access_token", "host": "example.com", "exp": time.time() + 3600},
            'test_secret',
            algorithm="HS256",
        )
        cache.set(f"{token}:example.com", "OK")
        response = self.app.get(f'/logout?token={token}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'Logged out')
        mock_post.assert_called_once_with(
            'https://discord.com/api/oauth2/token/revoke',
            data={
                'token': 'test_access_token',
                'client_id': 'test_id',
                'client_secret': 'test_secret',
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        self.assertIsNone(cache.get(f"{token}:example.com"))


if __name__ == '__main__':
    unittest.main()
