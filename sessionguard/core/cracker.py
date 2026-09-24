"""
High-performance HMAC-SHA256 dictionary cracker for SessionGuard.
Tests offline JWT signatures against dictionaries of common keys.
"""
import os
import time
import base64
import hmac
import hashlib
from typing import Optional, List, Tuple
from dataclasses import dataclass


DEFAULT_WORDLIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "wordlists",
    "jwt_secrets.txt"
)


@dataclass
class CrackerResult:
    cracked: bool
    secret: Optional[str]
    algorithm: str
    keys_tested: int
    elapsed_time: float
    keys_per_second: float


def _b64url_decode_to_bytes(segment: str) -> bytes:
    """Pad and decode base64url string to bytes."""
    rem = len(segment) % 4
    if rem > 0:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment.encode("utf-8"))


def crack_jwt_secret(
    raw_token: str,
    wordlist_path: Optional[str] = None,
    extra_candidates: Optional[List[str]] = None
) -> CrackerResult:
    """
    Attempts to crack an HMAC JWT secret using a dictionary attack.
    
    :param raw_token: Raw JWT string
    :param wordlist_path: Optional custom path to wordlist
    :param extra_candidates: Additional strings to test (e.g., username, empty string)
    :return: CrackerResult with cracked status and performance stats
    """
    cleaned = raw_token.strip()
    if cleaned.startswith("Bearer "):
        cleaned = cleaned[7:].strip()
        
    parts = cleaned.split(".")
    if len(parts) != 3:
        return CrackerResult(
            cracked=False,
            secret=None,
            algorithm="UNKNOWN",
            keys_tested=0,
            elapsed_time=0.0,
            keys_per_second=0.0
        )
        
    header_b64, payload_b64, signature_b64 = parts[0], parts[1], parts[2]
    
    # Check if signature exists
    if not signature_b64:
        return CrackerResult(
            cracked=False,
            secret=None,
            algorithm="none",
            keys_tested=0,
            elapsed_time=0.0,
            keys_per_second=0.0
        )
        
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    try:
        expected_sig_bytes = _b64url_decode_to_bytes(signature_b64)
    except Exception:
        return CrackerResult(
            cracked=False,
            secret=None,
            algorithm="UNKNOWN",
            keys_tested=0,
            elapsed_time=0.0,
            keys_per_second=0.0
        )

    # Determine hash algorithm from header
    alg = "HS256"
    try:
        import json
        hdr_bytes = _b64url_decode_to_bytes(header_b64)
        hdr = json.loads(hdr_bytes.decode("utf-8"))
        alg = hdr.get("alg", "HS256")
    except Exception:
        pass

    hash_fn = hashlib.sha256
    if alg == "HS384":
        hash_fn = hashlib.sha384
    elif alg == "HS512":
        hash_fn = hashlib.sha512
    elif alg not in ("HS256", "UNKNOWN"):
        # Asymmetric algorithm (e.g. RS256, ES256) cannot be cracked with HMAC dictionary
        return CrackerResult(
            cracked=False,
            secret=None,
            algorithm=alg,
            keys_tested=0,
            elapsed_time=0.0,
            keys_per_second=0.0
        )

    # Collect wordlist
    target_wordlist = wordlist_path or DEFAULT_WORDLIST_PATH
    candidates: List[str] = []
    
    if extra_candidates:
        candidates.extend([c.strip() for c in extra_candidates if c])
        
    # Always test common baseline edge cases
    candidates.extend(["", "secret", "password", "123456", "admin"])

    if os.path.exists(target_wordlist):
        try:
            with open(target_wordlist, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    candidate = line.strip()
                    if candidate and not candidate.startswith("#"):
                        candidates.append(candidate)
        except Exception:
            pass

    # Deduplicate while preserving order
    seen = set()
    unique_candidates = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique_candidates.append(c)

    start_time = time.perf_counter()
    tested_count = 0
    cracked_secret: Optional[str] = None

    for candidate in unique_candidates:
        tested_count += 1
        computed_sig = hmac.new(
            candidate.encode("utf-8"),
            signing_input,
            hash_fn
        ).digest()
        
        if hmac.compare_digest(computed_sig, expected_sig_bytes):
            cracked_secret = candidate
            break

    elapsed = time.perf_counter() - start_time
    keys_per_sec = (tested_count / elapsed) if elapsed > 0 else 0.0

    return CrackerResult(
        cracked=(cracked_secret is not None),
        secret=cracked_secret,
        algorithm=alg,
        keys_tested=tested_count,
        elapsed_time=elapsed,
        keys_per_second=keys_per_sec
    )
