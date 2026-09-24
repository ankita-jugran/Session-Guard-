"""
Scanner Orchestrator for SessionGuard.
Coordinates token decoding, check execution, and report generation.
"""
from typing import Optional, List
from sessionguard.core.decoder import decode_jwt, DecodedToken
from sessionguard.core.checks import ALL_CHECKS, CheckResult
from sessionguard.core.risk_engine import RiskEngine, AuditReport


class SessionGuardScanner:
    """Orchestrates security audits against JWT tokens and live endpoints."""

    def __init__(self, target_url: Optional[str] = None, wordlist_path: Optional[str] = None):
        self.target_url = target_url
        self.wordlist_path = wordlist_path

    def scan(self, raw_token: str) -> AuditReport:
        token: DecodedToken = decode_jwt(raw_token)

        # Build token metadata dictionary
        token_meta = {
            "algorithm": token.algorithm,
            "type": token.token_type,
            "subject": token.subject,
            "role": token.role,
            "jti": token.jti or "None",
            "issued_at": token.iat_human or "Not Specified",
            "expires_at": token.exp_human or "None (Indefinite)",
            "is_expired": token.is_expired,
            "remaining_time": token.remaining_lifetime_human,
            "total_lifetime": token.total_lifetime_human,
            "header": token.header,
            "payload": token.payload,
            "signature_preview": (token.signature[:16] + "...") if token.signature else "None",
            "raw_token_preview": (token.raw_token[:25] + "..." + token.raw_token[-10:]) if len(token.raw_token) > 35 else token.raw_token
        }

        # Run registered security checks
        results: List[CheckResult] = []
        for check_cls in ALL_CHECKS:
            check_instance = check_cls()
            result = check_instance.run(token, target_url=self.target_url)
            results.append(result)

        # Evaluate risk score and synthesis
        report = RiskEngine.evaluate(results, token_metadata=token_meta)
        return report


def scan_jwt(raw_token: str, target_url: Optional[str] = None) -> AuditReport:
    """Convenience helper to scan a token."""
    scanner = SessionGuardScanner(target_url=target_url)
    return scanner.scan(raw_token)
