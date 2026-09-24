"""
Security checks registry for SessionGuard.
"""
from sessionguard.core.checks.base import BaseCheck, CheckResult
from sessionguard.core.checks.weak_secret import WeakSecretCheck
from sessionguard.core.checks.alg_none import AlgNoneCheck
from sessionguard.core.checks.expiration import ExpirationCheck

ALL_CHECKS = [
    AlgNoneCheck,
    WeakSecretCheck,
    ExpirationCheck,
]

__all__ = [
    "BaseCheck",
    "CheckResult",
    "AlgNoneCheck",
    "WeakSecretCheck",
    "ExpirationCheck",
    "ALL_CHECKS",
]
