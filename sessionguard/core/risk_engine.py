"""
Risk Engine for SessionGuard.
Calculates Exploitability x Impact (1-9) scores and synthesizes security postures.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any
from sessionguard.core.checks.base import CheckResult


@dataclass
class AuditReport:
    """Consolidated risk assessment audit report."""
    raw_token_preview: str
    overall_score: int  # 1 to 9
    risk_level: str     # CRITICAL, HIGH, MEDIUM, LOW
    total_checks: int
    passed_count: int
    failed_count: int
    hijack_verdict: str
    check_results: List[CheckResult] = field(default_factory=list)
    remediations: List[Dict[str, str]] = field(default_factory=list)
    token_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "risk_level": self.risk_level,
            "total_checks": self.total_checks,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "hijack_verdict": self.hijack_verdict,
            "token_metadata": self.token_metadata,
            "checks": [r.to_dict() for r in self.check_results],
            "remediations": self.remediations
        }


class RiskEngine:
    """
    Evaluates individual check results, computes aggregate risk scores,
    and maps findings to OWASP ASVS and CWE standards.
    """

    @staticmethod
    def evaluate(check_results: List[CheckResult], token_metadata: Dict[str, Any] = None) -> AuditReport:
        if not check_results:
            return AuditReport(
                raw_token_preview="N/A",
                overall_score=1,
                risk_level="LOW",
                total_checks=0,
                passed_count=0,
                failed_count=0,
                hijack_verdict="No security checks executed.",
                check_results=[]
            )

        passed = [r for r in check_results if r.passed]
        failed = [r for r in check_results if not r.passed]
        
        # Determine overall score: Maximum severity among failed checks, default to 1 if all pass
        if failed:
            overall_score = max(r.score for r in failed)
        else:
            overall_score = 1

        # Classify risk level
        if overall_score >= 9:
            risk_level = "CRITICAL"
        elif overall_score >= 6:
            risk_level = "HIGH"
        elif overall_score >= 4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Generate Hijack Assessment Verdict (answers the central thesis question)
        has_bypass_or_cracked = any(r.check_id in ("weak_secret", "alg_none") and not r.passed for r in failed)
        has_excessive_exp = any(r.check_id == "expiration" and not r.passed for r in failed)

        if has_bypass_or_cracked:
            hijack_verdict = (
                "COMPLETE ACCOUNT TAKEOVER POSSIBLE: Attackers can forge arbitrary valid tokens "
                "or bypass cryptographic verification entirely. Session hijacking is trivial, "
                "immediate, and undetectable without server-side key rotation and code patching."
            )
        elif has_excessive_exp:
            hijack_verdict = (
                "PERSISTENT HIJACK WINDOW: Cryptographic signatures are intact, but an excessively long "
                "or indefinite token expiration window permits an attacker who obtains this token to maintain "
                "unauthorized session access for days or weeks without re-authentication."
            )
        elif not failed:
            hijack_verdict = (
                "HARDENED SESSION POSTURE: The token utilizes strong cryptographic signing and tight expiration "
                "bounds. Hijack risk is minimized in accordance with OWASP ASVS V3 recommendations."
            )
        else:
            hijack_verdict = (
                f"MODERATE RISK: {len(failed)} potential configuration weakness(es) identified. "
                "Review remediation steps to eliminate session replay and hijacking vectors."
            )

        # Collect prioritized remediations
        remediations = []
        # Sort failed checks by score descending
        sorted_failed = sorted(failed, key=lambda x: x.score, reverse=True)
        for r in sorted_failed:
            if r.remediation:
                remediations.append({
                    "check": r.name,
                    "cwe": r.cwe,
                    "severity": r.severity,
                    "score": f"{r.score}/9",
                    "action": r.remediation
                })

        token_meta = token_metadata or {}
        raw_preview = token_meta.get("raw_token_preview", "N/A")

        return AuditReport(
            raw_token_preview=raw_preview,
            overall_score=overall_score,
            risk_level=risk_level,
            total_checks=len(check_results),
            passed_count=len(passed),
            failed_count=len(failed),
            hijack_verdict=hijack_verdict,
            check_results=check_results,
            remediations=remediations,
            token_metadata=token_meta
        )
