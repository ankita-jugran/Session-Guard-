"""
Token Expiration and Lifetime Assessment Check for SessionGuard.
Evaluates the existence, remaining duration, and total lifetime of JWT sessions.
"""
import time
from typing import Optional
from sessionguard.core.decoder import DecodedToken
from sessionguard.core.checks.base import BaseCheck, CheckResult


class ExpirationCheck(BaseCheck):
    check_id = "expiration"
    name = "Session Expiration & Lifetime"
    cwe = "CWE-613: Insufficient Session Expiration"
    owasp = "OWASP A07:2021 - Identification and Authentication Failures / ASVS V3.3"

    # Thresholds in seconds
    RECOMMENDED_MAX_ACCESS_LIFETIME = 3600  # 1 hour max recommended for access tokens
    EXCESSIVE_LIFETIME_THRESHOLD = 86400 * 2  # > 48 hours is considered excessive

    def run(self, token: DecodedToken, target_url: Optional[str] = None) -> CheckResult:
        if not token.is_valid_format:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                passed=False,
                severity="INFO",
                exploitability=1,
                impact=1,
                score=1,
                title="Malformed Token",
                description=f"Cannot inspect expiration claims: {token.error}",
                cwe=self.cwe,
                owasp=self.owasp,
                remediation="Provide a valid JWT token."
            )

        # 1. Missing 'exp' claim check
        if token.exp is None:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                passed=False,
                severity="CRITICAL",
                exploitability=3,
                impact=3,
                score=9,
                title="CRITICAL: Missing 'exp' (Expiration) Claim",
                description=(
                    "The token does not define an 'exp' (Expiration Time) claim. "
                    "This token will be treated as valid indefinitely by standard JWT verifiers. "
                    "If intercepted or leaked, an attacker can maintain unauthorized access permanently."
                ),
                details={"exp": None, "iat": token.iat_human},
                cwe=self.cwe,
                owasp=self.owasp,
                remediation=(
                    "Always set a short 'exp' timestamp when minting JWTs (e.g. 15 to 60 minutes). "
                    "Use refresh token rotation for extending sessions."
                )
            )

        now = time.time()
        is_expired = token.is_expired
        time_to_exp = token.time_to_expiry_seconds or 0
        total_lifetime = token.lifetime_seconds

        # 2. Check for future 'iat' (timestamp tampering / severe clock skew)
        if token.iat and token.iat > now + 300:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                passed=False,
                severity="MEDIUM",
                exploitability=2,
                impact=2,
                score=4,
                title="Abnormal 'iat' Timestamp (Issued in Future)",
                description=f"Token 'iat' is set in the future ({token.iat_human}). Indicates server clock drift or forged claims.",
                details={"iat": token.iat_human, "current_time": token._format_timestamp(now)},
                cwe="CWE-384: Session Fixation",
                owasp=self.owasp,
                remediation="Ensure system clocks are synchronized via NTP and reject tokens with future 'iat' timestamps."
            )

        # 3. Excessive total lifetime (> 48 hours, e.g. 30 days)
        if total_lifetime is not None and total_lifetime > self.EXCESSIVE_LIFETIME_THRESHOLD:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                passed=False,
                severity="HIGH",
                exploitability=2,
                impact=3,
                score=6,
                title=f"HIGH: Excessive Session Lifetime ({token.total_lifetime_human})",
                description=(
                    f"The token was minted with a total validity window of {token.total_lifetime_human} "
                    f"({total_lifetime:,} seconds). "
                    "Industry standards (OWASP ASVS V3.3) recommend short-lived access tokens (15-30 minutes). "
                    "An excessively long expiration window gives session hijackers a wide attack opportunity."
                ),
                details={
                    "total_lifetime": token.total_lifetime_human,
                    "issued_at": token.iat_human,
                    "expires_at": token.exp_human,
                    "is_expired": is_expired,
                    "remaining_lifetime": token.remaining_lifetime_human
                },
                cwe=self.cwe,
                owasp=self.owasp,
                remediation=(
                    "Reduce JWT access token lifespan to 15-30 minutes (maximum 1 hour). "
                    "Implement a secure Refresh Token mechanism with server-side revocation to refresh access tokens."
                )
            )

        # 4. Moderate lifetime (> 1 hour, <= 48 hours)
        if total_lifetime is not None and total_lifetime > self.RECOMMENDED_MAX_ACCESS_LIFETIME:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                passed=False,
                severity="MEDIUM",
                exploitability=2,
                impact=2,
                score=4,
                title=f"MEDIUM: Token Lifetime Exceeds Recommended Best Practices ({token.total_lifetime_human})",
                description=(
                    f"The token lifetime is {token.total_lifetime_human}, which exceeds the 15-60 minute window "
                    f"recommended by OWASP for bearer tokens."
                ),
                details={
                    "total_lifetime": token.total_lifetime_human,
                    "issued_at": token.iat_human,
                    "expires_at": token.exp_human,
                    "is_expired": is_expired,
                    "remaining_lifetime": token.remaining_lifetime_human
                },
                cwe=self.cwe,
                owasp=self.owasp,
                remediation="Consider reducing access token lifetime to 15-30 minutes and pairing with refresh tokens."
            )

        # 5. Token is expired right now (informational / passed if lifetime was short)
        if is_expired:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                passed=True,
                severity="LOW",
                exploitability=1,
                impact=1,
                score=1,
                title="Passed: Token Has Expired",
                description=(
                    f"The token reached its expiration time on {token.exp_human} ({token.remaining_lifetime_human}). "
                    f"Initial lifetime was well-bounded ({token.total_lifetime_human})."
                ),
                details={
                    "total_lifetime": token.total_lifetime_human,
                    "expired_at": token.exp_human,
                    "is_expired": True
                },
                cwe=self.cwe,
                owasp=self.owasp,
                remediation="Normal lifecycle. The client must re-authenticate or use a refresh token."
            )

        # 6. Secure short-lived token
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            passed=True,
            severity="LOW",
            exploitability=1,
            impact=1,
            score=1,
            title=f"Passed: Short-Lived Access Token ({token.total_lifetime_human})",
            description=(
                f"The token specifies an expiration time of {token.exp_human} "
                f"({token.remaining_lifetime_human}). Total lifetime of {token.total_lifetime_human} "
                f"complies with OWASP ASVS session duration recommendations."
            ),
            details={
                "total_lifetime": token.total_lifetime_human,
                "remaining_lifetime": token.remaining_lifetime_human,
                "expires_at": token.exp_human
            },
            cwe=self.cwe,
            owasp=self.owasp,
            remediation="Maintain existing short expiration policy."
        )
