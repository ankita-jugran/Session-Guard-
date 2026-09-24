"""
Security profiles and configuration for Dummy Target App.
Supports dynamic switching between Vulnerable and Hardened modes.
"""

class SecurityProfile:
    def __init__(
        self,
        name: str,
        secret_key: str,
        allow_alg_none: bool,
        token_expiry_seconds: int,
        enforce_revocation: bool,
        storage_location: str,
        cookie_httponly: bool,
        device_fingerprint_check: bool,
        idle_timeout_seconds: int,
        description: str
    ):
        self.name = name
        self.secret_key = secret_key
        self.allow_alg_none = allow_alg_none
        self.token_expiry_seconds = token_expiry_seconds
        self.enforce_revocation = enforce_revocation
        self.storage_location = storage_location  # 'localStorage' or 'cookie'
        self.cookie_httponly = cookie_httponly
        self.device_fingerprint_check = device_fingerprint_check
        self.idle_timeout_seconds = idle_timeout_seconds
        self.description = description

    def to_dict(self):
        return {
            "name": self.name,
            "secret_key_strength": "weak ('secret')" if self.secret_key == "secret" else "strong (256-bit entropy)",
            "allow_alg_none": self.allow_alg_none,
            "token_expiry_seconds": self.token_expiry_seconds,
            "token_expiry_human": f"{self.token_expiry_seconds // 60}m" if self.token_expiry_seconds < 86400 else f"{self.token_expiry_seconds // 86400} days",
            "enforce_revocation": self.enforce_revocation,
            "storage_location": self.storage_location,
            "cookie_httponly": self.cookie_httponly,
            "device_fingerprint_check": self.device_fingerprint_check,
            "idle_timeout_seconds": self.idle_timeout_seconds,
            "description": self.description,
        }

PROFILE_VULNERABLE = SecurityProfile(
    name="vulnerable",
    secret_key="secret",
    allow_alg_none=True,
    token_expiry_seconds=86400 * 30,  # 30 days (Excessive session validity)
    enforce_revocation=False,          # Stateless logout: Token remains valid post-logout
    storage_location="localStorage",   # Vulnerable to XSS token theft
    cookie_httponly=False,
    device_fingerprint_check=False,    # Unrestricted token replay from any IP/client
    idle_timeout_seconds=0,            # No idle timeout check
    description="Intentionally vulnerable configuration demonstrating common JWT session management flaws."
)

PROFILE_HARDENED = SecurityProfile(
    name="hardened",
    secret_key="s3cur3_k3y_#9823!@_rand0m_jwt_s3ssi0n_gu@rd_t0k3n_2026_super_strong",
    allow_alg_none=False,
    token_expiry_seconds=900,          # 15 minutes (OWASP ASVS recommended)
    enforce_revocation=True,           # Active server-side token revocation table
    storage_location="cookie",         # HttpOnly, SameSite=Lax cookie storage
    cookie_httponly=True,
    device_fingerprint_check=True,     # Token bound to client fingerprint/User-Agent
    idle_timeout_seconds=300,          # 5 minutes idle inactivity timeout
    description="Hardened OWASP-compliant session configuration with strict signatures and revocation."
)

class AppConfig:
    """Active global configuration state."""
    current_profile = PROFILE_VULNERABLE

    @classmethod
    def set_mode(cls, mode_name: str) -> SecurityProfile:
        if mode_name.lower() == "hardened":
            cls.current_profile = PROFILE_HARDENED
        else:
            cls.current_profile = PROFILE_VULNERABLE
        return cls.current_profile

    @classmethod
    def get_profile(cls) -> SecurityProfile:
        return cls.current_profile
