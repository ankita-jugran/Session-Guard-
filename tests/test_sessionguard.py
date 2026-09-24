"""
Unit tests for SessionGuard Core (Part B).
Verifies JWT decoding, weak secret cracking, expiration check, and risk scoring engine.
"""
import time
import unittest
import jwt

from sessionguard.core.decoder import decode_jwt
from sessionguard.core.cracker import crack_jwt_secret
from sessionguard.core.checks.expiration import ExpirationCheck
from sessionguard.core.checks.weak_secret import WeakSecretCheck
from sessionguard.core.checks.alg_none import AlgNoneCheck, craft_unsigned_token
from sessionguard.core.risk_engine import RiskEngine
from sessionguard.scanner import SessionGuardScanner


class TestSessionGuardCore(unittest.TestCase):

    def test_decode_valid_token(self):
        """Test decoding a standard JWT without secret."""
        payload = {"sub": "user123", "role": "editor", "iat": int(time.time()), "exp": int(time.time()) + 3600}
        token_str = jwt.encode(payload, "any_secret", algorithm="HS256")

        decoded = decode_jwt(token_str)
        self.assertTrue(decoded.is_valid_format)
        self.assertEqual(decoded.algorithm, "HS256")
        self.assertEqual(decoded.subject, "user123")
        self.assertEqual(decoded.role, "editor")
        self.assertFalse(decoded.is_expired)
        self.assertIsNotNone(decoded.iat_human)
        self.assertIsNotNone(decoded.exp_human)

    def test_decode_malformed_token(self):
        """Test graceful failure on malformed token strings."""
        decoded = decode_jwt("not.a.valid.jwt.string")
        self.assertFalse(decoded.is_valid_format)
        self.assertIn("Invalid JWT structure", decoded.error)

    def test_crack_weak_secret(self):
        """Test that dictionary cracker quickly identifies weak secret 'secret'."""
        token_str = jwt.encode({"sub": "admin"}, "secret", algorithm="HS256")
        res = crack_jwt_secret(token_str)

        self.assertTrue(res.cracked)
        self.assertEqual(res.secret, "secret")
        self.assertGreater(res.keys_tested, 0)
        self.assertLess(res.elapsed_time, 1.0)  # Should complete in < 1 second

    def test_crack_strong_secret_fails(self):
        """Test that strong random key resists dictionary attack."""
        strong_key = "a_super_random_cryptographic_secret_key_32bytes_long!"
        token_str = jwt.encode({"sub": "admin"}, strong_key, algorithm="HS256")
        res = crack_jwt_secret(token_str)

        self.assertFalse(res.cracked)
        self.assertIsNone(res.secret)

    def test_expiration_check_missing_exp(self):
        """Test that missing exp claim triggers CRITICAL risk."""
        token_str = jwt.encode({"sub": "admin"}, "test_key", algorithm="HS256")
        decoded = decode_jwt(token_str)
        
        check = ExpirationCheck()
        res = check.run(decoded)

        self.assertFalse(res.passed)
        self.assertEqual(res.severity, "CRITICAL")
        self.assertEqual(res.score, 9)

    def test_expiration_check_excessive_lifetime(self):
        """Test that 30-day token lifetime triggers HIGH risk."""
        now = int(time.time())
        token_str = jwt.encode({"sub": "admin", "iat": now, "exp": now + 86400 * 30}, "key", algorithm="HS256")
        decoded = decode_jwt(token_str)

        check = ExpirationCheck()
        res = check.run(decoded)

        self.assertFalse(res.passed)
        self.assertEqual(res.severity, "HIGH")
        self.assertEqual(res.score, 6)

    def test_expiration_check_short_lifetime_passes(self):
        """Test that 15-minute token lifetime passes."""
        now = int(time.time())
        token_str = jwt.encode({"sub": "admin", "iat": now, "exp": now + 900}, "key", algorithm="HS256")
        decoded = decode_jwt(token_str)

        check = ExpirationCheck()
        res = check.run(decoded)

        self.assertTrue(res.passed)
        self.assertEqual(res.severity, "LOW")
        self.assertEqual(res.score, 1)

    def test_craft_unsigned_token(self):
        """Test unsigned token generation for alg:none check."""
        payload = {"sub": "attacker", "role": "admin"}
        unsigned = craft_unsigned_token(payload)
        
        parts = unsigned.split(".")
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[2], "")  # Empty signature

        decoded = decode_jwt(unsigned)
        self.assertEqual(decoded.algorithm, "none")
        self.assertEqual(decoded.subject, "attacker")

    def test_full_scanner_vulnerable_and_hardened(self):
        """Test end-to-end scanner execution on both vulnerable and hardened tokens."""
        scanner = SessionGuardScanner()

        # 1. Vulnerable token
        vuln_token = jwt.encode(
            {"sub": "alice", "role": "user", "iat": int(time.time()), "exp": int(time.time()) + 86400 * 30},
            "secret",
            algorithm="HS256"
        )
        vuln_report = scanner.scan(vuln_token)
        self.assertEqual(vuln_report.risk_level, "CRITICAL")
        self.assertEqual(vuln_report.overall_score, 9)
        self.assertGreater(vuln_report.failed_count, 0)

        # 2. Hardened token
        hard_token = jwt.encode(
            {"sub": "alice", "role": "user", "iat": int(time.time()), "exp": int(time.time()) + 900},
            "a_super_random_cryptographic_secret_key_32bytes_long!",
            algorithm="HS256"
        )
        hard_report = scanner.scan(hard_token)
        self.assertEqual(hard_report.risk_level, "LOW")
        self.assertEqual(hard_report.overall_score, 1)
        self.assertEqual(hard_report.failed_count, 0)


if __name__ == "__main__":
    unittest.main()
