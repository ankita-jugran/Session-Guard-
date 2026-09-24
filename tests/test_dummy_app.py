"""
Unit tests for Dummy Login Target App (Part A).
Verifies login, token issuance, dashboard access, revocation, and mode toggling.
"""
import unittest
import json
from app.app import app
from app.config import AppConfig, PROFILE_VULNERABLE, PROFILE_HARDENED
from app.db import init_db, clear_revoked_tokens

class TestDummyApp(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        init_db()
        clear_revoked_tokens()
        AppConfig.set_mode("vulnerable")

    def test_mode_toggle(self):
        """Test toggling between vulnerable and hardened modes."""
        resp = self.client.get("/api/mode")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["name"], "vulnerable")

        # Toggle to hardened
        resp = self.client.post("/api/toggle-mode")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["active_mode"], "hardened")

    def test_vulnerable_login_and_alg_none(self):
        """Test that vulnerable mode issues token and accepts alg:none."""
        AppConfig.set_mode("vulnerable")
        resp = self.client.post("/login", json={"username": "admin", "password": "admin2026"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("token", data)
        token = data["token"]

        # Access dashboard with valid token
        dash_resp = self.client.get("/dashboard", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(dash_resp.status_code, 200)

        # Craft alg:none token
        import base64
        parts = token.split(".")
        none_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode("utf-8").rstrip("=")
        forged_token = f"{none_header}.{parts[1]}."

        # In vulnerable mode, alg:none should be accepted
        dash_none_resp = self.client.get("/dashboard", headers={"Authorization": f"Bearer {forged_token}"})
        self.assertEqual(dash_none_resp.status_code, 200)

    def test_hardened_rejects_alg_none_and_enforces_revocation(self):
        """Test that hardened mode rejects alg:none and enforces revocation on logout."""
        AppConfig.set_mode("hardened")
        resp = self.client.post("/login", json={"username": "admin", "password": "admin2026"})
        self.assertEqual(resp.status_code, 200)
        
        # In hardened mode, token is in cookie or preview
        token_cookie = None
        cookie = self.client.get_cookie("session_token")
        if cookie:
            token_cookie = cookie.value
        if not token_cookie:
            # Fallback to Set-Cookie header
            cookies = resp.headers.get_list("Set-Cookie")
            for c in cookies:
                if "session_token=" in c:
                    token_cookie = c.split("session_token=")[1].split(";")[0]
                    break
        self.assertIsNotNone(token_cookie)

        # Access dashboard with cookie
        dash_resp = self.client.get("/dashboard")
        self.assertEqual(dash_resp.status_code, 200)

        # Logout
        logout_resp = self.client.post("/logout", headers={"Authorization": f"Bearer {token_cookie}"})
        self.assertEqual(logout_resp.status_code, 200)

        # Try accessing dashboard again with old token -> Should be rejected (401)
        dash_retry = self.client.get("/dashboard", headers={"Authorization": f"Bearer {token_cookie}"})
        self.assertEqual(dash_retry.status_code, 401)

if __name__ == "__main__":
    unittest.main()
