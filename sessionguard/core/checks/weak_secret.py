"""
Weak Secret Key Check for SessionGuard.
Evaluates HMAC token resilience against offline dictionary attacks.
"""
from typing import Optional
from sessionguard.core.decoder import DecodedToken
from sessionguard.core.checks.base import BaseCheck, CheckResult
from sessionguard.core.cracker import crack_jwt_secret


class WeakSecretCheck(BaseCheck):
    check_id = "weak_secret"
    name = "HMAC Secret Key Strength"
    cwe = "CWE-798: Use of Hard-coded Credentials (also CWE-522)"
    owasp = "OWASP A07:2021 - Identification and Authentication Failures / ASVS V3.5"

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
                description=f"Cannot test signing secret: {token.error}",
                cwe=self.cwe,
                owasp=self.owasp,
                remediation="Ensure the client receives a syntactically valid JWT (header.payload.signature)."
            )

        alg = token.algorithm.upper()

        if alg == "NONE":
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                passed=False,
                severity="HIGH",
                exploitability=3,
                impact=3,
                score=9,
                title="No Signature Algorithm Used (alg: none)",
                description="The token specifies algorithm 'none' and has no cryptographic signature to crack.",
                cwe="CWE-347: Improper Verification of Cryptographic Signature",
                owasp=self.owasp,
                remediation="Configure the server to enforce HS256, RS256, or ES256 and reject unsigned tokens."
            )

        if not alg.startswith("HS"):
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                passed=True,
                severity="INFO",
                exploitability=1,
                impact=1,
                score=1,
                title=f"Asymmetric Algorithm In Use ({alg})",
                description=f"The token uses an asymmetric algorithm ({alg}), which is not vulnerable to symmetric dictionary cracking.",
                details={"algorithm": alg},
                cwe=self.cwe,
                owasp=self.owasp,
                remediation="Ensure the corresponding private key is stored securely (e.g. AWS KMS, HashiCorp Vault) and public keys are verified against a trusted JWKS endpoint."
            )

        # Symmetric HMAC algorithm: perform offline crack test
        extra_candidates = []
        if token.subject and token.subject != "Anonymous":
            extra_candidates.append(token.subject)
        if token.role and token.role != "None":
            extra_candidates.append(token.role)

        crack_res = crack_jwt_secret(token.raw_token, extra_candidates=extra_candidates)

        if crack_res.cracked:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                passed=False,
                severity="CRITICAL",
                exploitability=3,
                impact=3,
                score=9,
                title=f"CRITICAL: Trivial Secret Key Cracked ('{crack_res.secret}')",
                description=(
                    f"The token's HMAC signing secret was cracked offline in {crack_res.elapsed_time*1000:.2f}ms "
                    f"after testing {crack_res.keys_tested} candidates. "
                    f"The secret key is '{crack_res.secret}'. An attacker can forge valid tokens for any user or role."
                ),
                details={
                    "cracked": True,
                    "secret": crack_res.secret,
                    "algorithm": crack_res.algorithm,
                    "keys_tested": crack_res.keys_tested,
                    "speed_keys_per_sec": int(crack_res.keys_per_second),
                    "elapsed_ms": round(crack_res.elapsed_time * 1000, 2)
                },
                cwe=self.cwe,
                owasp=self.owasp,
                remediation=(
                    "Generate a cryptographically secure key of at least 256 bits using a CSPRNG "
                    "(e.g., python -c 'import secrets; print(secrets.token_hex(32))'). "
                    "Store it in an environment variable or secrets manager, never hardcoded."
                )
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            passed=True,
            severity="LOW",
            exploitability=1,
            impact=1,
            score=1,
            title="Passed: Secret Resisted Dictionary Attack",
            description=(
                f"HMAC secret could not be cracked against common dictionary wordlist. "
                f"Tested {crack_res.keys_tested} known keys in {crack_res.elapsed_time*1000:.2f}ms."
            ),
            details={
                "cracked": False,
                "keys_tested": crack_res.keys_tested,
                "elapsed_ms": round(crack_res.elapsed_time * 1000, 2)
            },
            cwe=self.cwe,
            owasp=self.owasp,
            remediation="Continue maintaining high entropy for signing keys. Rotate keys periodically."
        )
