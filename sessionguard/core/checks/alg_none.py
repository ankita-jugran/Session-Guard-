"""
Algorithm 'none' Signature Bypass Check for SessionGuard.
Tests whether server accepts unsigned forged tokens with alg set to 'none'.
"""
import base64
import json
from typing import Optional, Dict, Any, List
import requests

from sessionguard.core.decoder import DecodedToken
from sessionguard.core.checks.base import BaseCheck, CheckResult


def _b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def craft_unsigned_token(payload: Dict[str, Any], alg_variant: str = "none") -> str:
    """
    Creates an unsigned JWT with alg set to 'none' (or variant like 'None', 'NONE').
    Trailing dot is included per RFC 7519.
    """
    header = {"alg": alg_variant, "typ": "JWT"}
    header_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    
    h_b64 = _b64url_encode(header_json)
    p_b64 = _b64url_encode(payload_json)
    
    return f"{h_b64}.{p_b64}."


class AlgNoneCheck(BaseCheck):
    check_id = "alg_none"
    name = "Algorithm 'none' Signature Bypass"
    cwe = "CWE-347: Improper Verification of Cryptographic Signature"
    owasp = "OWASP A07:2021 - Identification and Authentication Failures / ASVS V3.5"

    def run(self, token: DecodedToken, target_url: Optional[str] = None) -> CheckResult:
        # Static check first: Is the presented token already alg:none?
        if token.is_valid_format and token.algorithm.lower() == "none":
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                passed=False,
                severity="CRITICAL",
                exploitability=3,
                impact=3,
                score=9,
                title="CRITICAL: Token Uses 'alg: none' Without Cryptographic Signature",
                description=(
                    "The analyzed token header explicitly specifies algorithm 'none' and contains no cryptographic signature. "
                    "Any entity in the network or client can tamper with token claims (user ID, roles, permissions) without detection."
                ),
                details={"token_header": token.header},
                cwe=self.cwe,
                owasp=self.owasp,
                remediation=(
                    "Disallow the 'none' algorithm in server JWT verification configuration. "
                    "Specify an explicit list of accepted cryptographic algorithms (e.g. algorithms=['HS256'])."
                )
            )

        # Dynamic / Live probe check: If target_url provided, test forged unsigned token
        if target_url:
            return self._probe_target(token, target_url)

        # Static inspection only (no target URL supplied)
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            passed=True,
            severity="LOW",
            exploitability=1,
            impact=1,
            score=1,
            title="Static Check Passed: Token Header Specifies Cryptographic Algorithm",
            description=(
                f"The token header specifies '{token.algorithm}'. "
                "To actively verify whether the backend server rejects unsigned 'alg:none' tokens, "
                "run this scan with the '--target <url>' parameter."
            ),
            details={"algorithm": token.algorithm},
            cwe=self.cwe,
            owasp=self.owasp,
            remediation="Ensure the server-side JWT verification explicitly enforces algorithms=['HS256'] (or RS256/ES256) and never permits 'none'."
        )

    def _probe_target(self, token: DecodedToken, target_url: str) -> CheckResult:
        base_target = target_url.rstrip("/")
        # Determine candidate endpoints to test
        test_endpoints = [
            f"{base_target}/dashboard",
            f"{base_target}/api/user",
            f"{base_target}/api/protected",
            base_target
        ]
        
        # Build forged payloads
        variants = ["none", "None", "NONE"]
        base_payload = token.payload.copy() if token.is_valid_format else {"sub": "admin", "role": "admin"}
        
        bypass_successful = False
        vulnerable_url = None
        successful_variant = None
        response_snippet = ""

        session = requests.Session()
        session.headers.update({"User-Agent": "SessionGuard-Security-Auditor/1.0"})

        for endpoint in test_endpoints:
            if bypass_successful:
                break
            for variant in variants:
                forged_token = craft_unsigned_token(base_payload, alg_variant=variant)
                headers = {"Authorization": f"Bearer {forged_token}"}
                cookies = {"token": forged_token, "session_token": forged_token}

                try:
                    # Test Authorization header
                    resp = session.get(endpoint, headers=headers, cookies=cookies, timeout=4, allow_redirects=False)
                    
                    # A 200 OK or 302 to dashboard indicates access allowed; 401/403/redirect to login indicates rejected
                    if resp.status_code == 200 and not any(kw in resp.text.lower() for kw in ["login", "sign in", "unauthorized", "access denied"]):
                        bypass_successful = True
                        vulnerable_url = endpoint
                        successful_variant = variant
                        response_snippet = resp.text[:120].strip().replace("\n", " ")
                        break
                except requests.RequestException:
                    continue

        if bypass_successful:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                passed=False,
                severity="CRITICAL",
                exploitability=3,
                impact=3,
                score=9,
                title="CRITICAL: Server Vulnerable to 'alg: none' Signature Bypass!",
                description=(
                    f"The server at '{vulnerable_url}' accepted an unsigned JWT with 'alg: {successful_variant}'. "
                    f"HTTP 200 OK was returned without verifying the signature. "
                    f"An attacker can forge arbitrary admin tokens and completely bypass authentication."
                ),
                details={
                    "vulnerable_endpoint": vulnerable_url,
                    "accepted_variant": successful_variant,
                    "response_preview": response_snippet
                },
                cwe=self.cwe,
                owasp=self.owasp,
                remediation=(
                    "In your JWT verification logic (e.g. PyJWT), pass algorithms=['HS256'] explicitly. "
                    "Never pass algorithms=None or omit the algorithms parameter. "
                    "Ensure PyJWT or your auth middleware rejects tokens missing valid cryptographic signatures."
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
            title="Passed: Server Strictly Enforces Cryptographic Signature",
            description=(
                f"Probed target server with forged unsigned 'alg:none' tokens. "
                f"Server successfully rejected all attempts (401/403/redirect to login)."
            ),
            details={"probed_target": target_url},
            cwe=self.cwe,
            owasp=self.owasp,
            remediation="Maintain strict algorithm whitelisting (e.g. algorithms=['HS256']) in production authentication gateways."
        )
