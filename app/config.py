"""
Security profiles and configuration for Dummy Target App.
Supports dynamic switching between Vulnerable and Secure modes.
"""

class SecurityProfile:
    def __init__(
        self,
        name: str,
        secret_keys: dict,
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
        self.secret_keys = secret_keys
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
            "secret_key_strength": "weak (dictionary)" if self.name == "vulnerable" else "strong (256-bit entropy)",
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
    secret_keys={
        "vuln-key-1": "secret",
        "vuln-key-2": "password",
        "vuln-key-3": "admin123",
        "vuln-key-4": "123456"
    },
    allow_alg_none=True,
    token_expiry_seconds=86400 * 30,  # 30 days (Excessive session validity)
    enforce_revocation=False,          # Stateless logout: Token remains valid post-logout
    storage_location="localStorage",   # Vulnerable to XSS token theft
    cookie_httponly=False,
    device_fingerprint_check=False,    # Unrestricted token replay from any IP/client
    idle_timeout_seconds=0,            # No idle timeout check
    description="Intentionally vulnerable configuration demonstrating common JWT session management flaws."
)

PROFILE_SECURE = SecurityProfile(
    name="secure",
    secret_keys={
        "hard-key-1": "s3cur3_k3y_#9823!@_rand0m_jwt_s3ssi0n_gu@rd_t0k3n_2026_super_strong",
        "hard-key-2": "an0th3r_v3ry_l0ng_and_c0mpl3x_s3cr3t_k3y_f0r_r0tati0n_991823!",
        "hard-key-3": "y3t_an0th3r_crypt0graph1cally_s3cur3_k3y_847294827394872"
    },
    allow_alg_none=False,
    token_expiry_seconds=900,          # 15 minutes (OWASP ASVS recommended)
    enforce_revocation=True,           # Active server-side token revocation table
    storage_location="cookie",         # HttpOnly, SameSite=Lax cookie storage
    cookie_httponly=True,
    device_fingerprint_check=True,     # Token bound to client fingerprint/User-Agent
    idle_timeout_seconds=300,          # 5 minutes idle inactivity timeout
    description="Secure OWASP-compliant session configuration with strict signatures and revocation."
)

class AppConfig:
    """Active global configuration state."""
    current_profile = PROFILE_VULNERABLE

    @classmethod
    def set_mode(cls, mode_name: str) -> SecurityProfile:
        if mode_name.lower() == "secure":
            cls.current_profile = PROFILE_SECURE
        else:
            cls.current_profile = PROFILE_VULNERABLE
        return cls.current_profile

    @classmethod
    def get_profile(cls) -> SecurityProfile:
        return cls.current_profile
