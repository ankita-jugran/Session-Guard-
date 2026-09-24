"""
JWT Decoder and Claim Humanizer for SessionGuard.
Safely extracts and parses JWT components without requiring verification keys.
"""
import base64
import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

class DecodedToken:
    def __init__(
        self,
        raw_token: str,
        header: Dict[str, Any],
        payload: Dict[str, Any],
        signature: str,
        header_b64: str,
        payload_b64: str,
        is_valid_format: bool = True,
        error: Optional[str] = None
    ):
        self.raw_token = raw_token.strip()
        self.header = header
        self.payload = payload
        self.signature = signature
        self.header_b64 = header_b64
        self.payload_b64 = payload_b64
        self.is_valid_format = is_valid_format
        self.error = error
        
        # Computed claims metadata
        self.algorithm = header.get("alg", "UNKNOWN")
        self.token_type = header.get("typ", "JWT")
        self.subject = payload.get("sub", "Anonymous")
        self.role = payload.get("role", "None")
        self.jti = payload.get("jti", None)
        
        # Expiry & timestamps analysis
        self.iat = payload.get("iat")
        self.exp = payload.get("exp")
        self.nbf = payload.get("nbf")
        
        self.iat_human = self._format_timestamp(self.iat)
        self.exp_human = self._format_timestamp(self.exp)
        self.nbf_human = self._format_timestamp(self.nbf)
        
        self.is_expired = False
        self.time_to_expiry_seconds = None
        self.lifetime_seconds = None
        
        self._analyze_timestamps()

    def _format_timestamp(self, ts: Optional[int]) -> Optional[str]:
        if ts is None or not isinstance(ts, (int, float)):
            return None
        try:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return str(ts)

    def _analyze_timestamps(self):
        now = time.time()
        if self.exp is not None and isinstance(self.exp, (int, float)):
            self.time_to_expiry_seconds = int(self.exp - now)
            self.is_expired = self.time_to_expiry_seconds <= 0
            
        if self.iat is not None and self.exp is not None:
            if isinstance(self.iat, (int, float)) and isinstance(self.exp, (int, float)):
                self.lifetime_seconds = int(self.exp - self.iat)

    @property
    def remaining_lifetime_human(self) -> str:
        if self.exp is None:
            return "Indefinite (No 'exp' claim)"
        if self.is_expired:
            abs_seconds = abs(self.time_to_expiry_seconds or 0)
            return f"Expired {self._humanize_seconds(abs_seconds)} ago"
        return f"{self._humanize_seconds(self.time_to_expiry_seconds or 0)} remaining"

    @property
    def total_lifetime_human(self) -> str:
        if self.lifetime_seconds is None:
            return "Unknown"
        return self._humanize_seconds(self.lifetime_seconds)

    @staticmethod
    def _humanize_seconds(seconds: int) -> str:
        if seconds <= 0:
            return "0s"
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, secs = divmod(rem, 60)
        
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if secs > 0 or not parts:
            parts.append(f"{secs}s")
        return " ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "type": self.token_type,
            "subject": self.subject,
            "role": self.role,
            "jti": self.jti,
            "header": self.header,
            "payload": self.payload,
            "signature_preview": self.signature[:16] + "..." if self.signature else "None",
            "timestamps": {
                "issued_at": self.iat_human,
                "expires_at": self.exp_human,
                "is_expired": self.is_expired,
                "remaining_lifetime": self.remaining_lifetime_human,
                "total_lifetime": self.total_lifetime_human,
            }
        }


def _b64url_decode(segment: str) -> str:
    """Pad and decode base64url string."""
    rem = len(segment) % 4
    if rem > 0:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment.encode("utf-8")).decode("utf-8", errors="replace")


def decode_jwt(raw_token: str) -> DecodedToken:
    """
    Parse and decode a JWT string without cryptographic verification.
    """
    cleaned = raw_token.strip()
    if cleaned.startswith("Bearer "):
        cleaned = cleaned[7:].strip()
        
    parts = cleaned.split(".")
    if len(parts) != 3:
        return DecodedToken(
            raw_token=cleaned,
            header={},
            payload={},
            signature="",
            header_b64="",
            payload_b64="",
            is_valid_format=False,
            error=f"Invalid JWT structure: Expected 3 segments separated by dots, found {len(parts)}."
        )

    header_b64, payload_b64, sig_b64 = parts[0], parts[1], parts[2]

    try:
        header_json = _b64url_decode(header_b64)
        header = json.loads(header_json)
    except Exception as e:
        return DecodedToken(
            raw_token=cleaned,
            header={},
            payload={},
            signature=sig_b64,
            header_b64=header_b64,
            payload_b64=payload_b64,
            is_valid_format=False,
            error=f"Failed to decode token header: {str(e)}"
        )

    try:
        payload_json = _b64url_decode(payload_b64)
        payload = json.loads(payload_json)
    except Exception as e:
        return DecodedToken(
            raw_token=cleaned,
            header=header,
            payload={},
            signature=sig_b64,
            header_b64=header_b64,
            payload_b64=payload_b64,
            is_valid_format=False,
            error=f"Failed to decode token payload: {str(e)}"
        )

    return DecodedToken(
        raw_token=cleaned,
        header=header,
        payload=payload,
        signature=sig_b64,
        header_b64=header_b64,
        payload_b64=payload_b64,
        is_valid_format=True
    )
