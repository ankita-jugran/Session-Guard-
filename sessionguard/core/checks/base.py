"""
Base Check definition and CheckResult schema for SessionGuard.
All security plugins inherit from BaseCheck.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from sessionguard.core.decoder import DecodedToken


@dataclass
class CheckResult:
    """Represents the findings of an individual security check."""
    check_id: str
    name: str
    passed: bool
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    exploitability: int  # 1 (Low), 2 (Medium), 3 (High)
    impact: int  # 1 (Low), 2 (Medium), 3 (High)
    score: int  # exploitability * impact (1 to 9)
    title: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    cwe: str = "N/A"
    owasp: str = "N/A"
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "passed": self.passed,
            "severity": self.severity,
            "exploitability": self.exploitability,
            "impact": self.impact,
            "score": self.score,
            "title": self.title,
            "description": self.description,
            "details": self.details,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "remediation": self.remediation
        }


class BaseCheck(ABC):
    """Abstract base class for all SessionGuard security checks."""
    
    check_id: str = "base"
    name: str = "Base Security Check"
    cwe: str = "N/A"
    owasp: str = "N/A"

    @abstractmethod
    def run(self, token: DecodedToken, target_url: Optional[str] = None) -> CheckResult:
        """
        Execute the check on the provided token and optional target server.
        
        :param token: The decoded JWT object.
        :param target_url: Optional live server URL (e.g., http://localhost:5000)
        :return: CheckResult containing findings, severity, score, and remediation.
        """
        pass
