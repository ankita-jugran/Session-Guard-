"""
Dummy Login Web Application (Test Target for SessionGuard).
Provides /login, /dashboard, /logout with configurable Vulnerable and Secure modes.
"""
import base64
import json
import time
import uuid
import hashlib
from typing import Tuple, Optional, Dict, Any

from flask import (
    Flask, request, jsonify, render_template, redirect, url_for, make_response
)
import jwt

from .config import AppConfig, PROFILE_VULNERABLE, PROFILE_SECURE
from .db import (
    init_db, verify_user, register_user, update_password,
    revoke_token, revoke_all_user_tokens, is_token_revoked,
    get_revoked_tokens, clear_revoked_tokens
)

app = Flask(__name__)
app.config["SECRET_KEY"] = "flask_internal_session_secret"

# Initialize SQLite database on startup
init_db()

def get_client_fingerprint() -> str:
    """Compute device fingerprint from User-Agent and headers."""
    ua = request.headers.get("User-Agent", "Unknown-Agent")
    return hashlib.sha256(ua.encode("utf-8")).hexdigest()[:16]

def extract_token() -> Optional[str]:
    """Extract JWT from Authorization header, Cookie, or form body."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    
    # Check Cookie
    cookie_token = request.cookies.get("session_token")
    if cookie_token:
        return cookie_token.strip()
    
    # Fallback to query param
    query_token = request.args.get("token")
    if query_token:
        return query_token.strip()
        
    return None

def decode_token_unverified(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Decode header and payload without verifying signature."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}, {}
        
        header_b64 = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
        payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        
        header = json.loads(base64.urlsafe_b64decode(header_b64.encode("utf-8")).decode("utf-8"))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8"))
        return header, payload
    except Exception:
        return {}, {}

def validate_session_token(token: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Validate token according to current security profile.
    Returns: (is_valid, payload_or_none, error_message_or_none)
    """
    profile = AppConfig.get_profile()
    
    header, raw_payload = decode_token_unverified(token)
    if not header or not raw_payload:
        return False, None, "Malformed or undecodable JWT token"

    alg = header.get("alg", "")

    # 1. Check alg:none bypass vulnerability
    if alg.lower() == "none" or alg == "":
        if profile.allow_alg_none:
            # Vulnerable Mode: Accepts alg:none with unverified payload
            payload = raw_payload
        else:
            return False, None, "Rejected: Algorithm 'none' is disallowed. Cryptographic signature required (CWE-347)."
    else:
        # Standard cryptographic verification
        try:
            kid = header.get("kid")
            if kid and kid in profile.secret_keys:
                secret = profile.secret_keys[kid]
            else:
                # Fallback to first key if kid missing (for backward compatibility)
                secret = list(profile.secret_keys.values())[0]

            payload = jwt.decode(
                token,
                secret,
                algorithms=["HS256"],
                options={"verify_exp": False} # We check exp explicitly below for custom feedback
            )
        except jwt.InvalidSignatureError:
            return False, None, "Invalid signature: Signature verification failed"
        except Exception as e:
            return False, None, f"Token decode error: {str(e)}"

    # 2. Check Expiration claim
    exp = payload.get("exp")
    if exp is not None:
        if time.time() > exp:
            return False, None, f"Token expired at {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(exp))} (CWE-613)"
    else:
        if not profile.allow_alg_none:
            return False, None, "Missing mandatory 'exp' claim in token"

    # 3. Check Server-Side Revocation (Blacklist)
    if profile.enforce_revocation:
        jti = payload.get("jti")
        username = payload.get("sub")
        if is_token_revoked(token, jti, username):
            return False, None, "Token has been revoked/invalidated on server (CWE-613 / OWASP ASVS V3.3)"

    # 4. Check Device Fingerprint / Replay Binding
    if profile.device_fingerprint_check:
        token_fp = payload.get("fp")
        current_fp = get_client_fingerprint()
        if token_fp and token_fp != current_fp:
            return False, None, "Device context mismatch: Token bound to another client fingerprint"

    # 5. Check Idle Inactivity Timeout
    if profile.idle_timeout_seconds > 0:
        last_active = payload.get("last_active", payload.get("iat", 0))
        if time.time() - last_active > profile.idle_timeout_seconds:
            return False, None, "Session invalidated due to inactivity (idle timeout exceeded)"

    return True, payload, None


# --- Web Routes ---

@app.route("/")
def index():
    token = extract_token()
    if token:
        valid, _, _ = validate_session_token(token)
        if valid:
            return redirect(url_for("dashboard"))
    return redirect(url_for("login_page"))

@app.route("/login", methods=["GET", "POST"])
def login_page():
    profile = AppConfig.get_profile()
    
    if request.method == "POST":
        # Supports JSON and Form submissions
        data = request.get_json(silent=True) or request.form
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()

        user = verify_user(username, password)
        if not user:
            if request.is_json:
                return jsonify({"success": False, "error": "Invalid username or password"}), 401
            return render_template("login.html", error="Invalid username or password", profile=profile.to_dict())

        # Generate JWT claims
        now = int(time.time())
        claims = {
            "sub": user["username"],
            "role": user["role"],
            "iat": now,
            "exp": now + profile.token_expiry_seconds,
            "jti": str(uuid.uuid4()),
        }
        
        if profile.device_fingerprint_check:
            claims["fp"] = get_client_fingerprint()
        if profile.idle_timeout_seconds > 0:
            claims["last_active"] = now

        # Select a random key from the active profile
        import random
        kid = random.choice(list(profile.secret_keys.keys()))
        secret = profile.secret_keys[kid]

        # Sign JWT
        token = jwt.encode(claims, secret, algorithm="HS256", headers={"kid": kid})

        # Handle delivery based on active storage profile
        if profile.storage_location == "cookie":
            # Secure / Cookie mode
            resp = make_response(
                jsonify({
                    "success": True,
                    "message": "Login successful. Session token saved in HttpOnly Cookie.",
                    "storage": "cookie",
                    "redirect_url": url_for("dashboard"),
                    "user": {"username": user["username"], "role": user["role"]},
                    "token_preview": token[:24] + "..."
                }) if (request.is_json or "application/json" in request.headers.get("Accept", "")) else redirect(url_for("dashboard"))
            )
            resp.set_cookie(
                "session_token",
                token,
                max_age=profile.token_expiry_seconds,
                httponly=profile.cookie_httponly,
                samesite="Lax",
                path="/"
            )
            return resp
        else:
            # Vulnerable / localStorage mode: Token delivered in body for JavaScript storage
            if request.is_json or "application/json" in request.headers.get("Accept", ""):
                return jsonify({
                    "success": True,
                    "message": "Login successful. Token delivered in response body for localStorage.",
                    "storage": "localStorage",
                    "token": token,
                    "redirect_url": url_for("dashboard", token=token),
                    "user": {"username": user["username"], "role": user["role"]}
                }), 200
            
            # For browser form post, render page that stores in localStorage and redirects
            return render_template(
                "login.html",
                token_to_store=token,
                redirect_url=url_for("dashboard", token=token),
                user=user,
                profile=profile.to_dict()
            )

    return render_template("login.html", profile=profile.to_dict())

@app.route("/register", methods=["POST"])
def register_page():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "user").strip()

    if not username or not password:
        if request.is_json or "application/json" in request.headers.get("Accept", ""):
            return jsonify({"success": False, "error": "Username and password are required"}), 400
        return render_template("login.html", error="Username and password are required", profile=AppConfig.get_profile().to_dict()), 400

    success, msg = register_user(username, password, role)
    if not success:
        if request.is_json or "application/json" in request.headers.get("Accept", ""):
            return jsonify({"success": False, "error": msg}), 400
        return render_template("login.html", error=msg, profile=AppConfig.get_profile().to_dict()), 400

    if request.is_json or "application/json" in request.headers.get("Accept", ""):
        return jsonify({"success": True, "message": msg}), 201
    return render_template("login.html", success_msg=msg, profile=AppConfig.get_profile().to_dict())

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "").strip()
    new_password = data.get("new_password", "").strip()

    if not username or not new_password:
        return jsonify({"success": False, "error": "Username and new password are required"}), 400

    success, msg = update_password(username, new_password)
    if not success:
        return jsonify({"success": False, "error": msg}), 400

    profile = AppConfig.get_profile()
    if profile.enforce_revocation:
        # In secure mode, invalidate all active tokens for this user
        revoke_all_user_tokens(username, reason="password_reset")

    return jsonify({
        "success": True,
        "message": msg,
        "active_sessions_revoked": profile.enforce_revocation,
        "warning": None if profile.enforce_revocation else "Vulnerable mode: Pre-existing session tokens remain valid after password reset!"
    }), 200

@app.route("/dashboard")
def dashboard():
    profile = AppConfig.get_profile()
    token = extract_token()

    if not token:
        if request.is_json or "application/json" in request.headers.get("Accept", ""):
            return jsonify({"error": "Unauthorized: Missing session token"}), 401
        return redirect(url_for("login_page", error="Please log in first"))

    valid, payload, error_msg = validate_session_token(token)
    if not valid:
        if request.is_json or "application/json" in request.headers.get("Accept", ""):
            return jsonify({"error": "Unauthorized", "details": error_msg}), 401
        return render_template("login.html", error=f"Access Denied: {error_msg}", profile=profile.to_dict()), 401

    header, _ = decode_token_unverified(token)

    if request.is_json:
        return jsonify({
            "status": "authorized",
            "user": payload.get("sub"),
            "role": payload.get("role"),
            "token_claims": payload,
            "token_header": header,
            "security_profile": profile.to_dict()
        }), 200

    return render_template(
        "dashboard.html",
        token=token,
        header=header,
        payload=payload,
        profile=profile.to_dict()
    )

@app.route("/logout", methods=["POST", "GET"])
def logout():
    profile = AppConfig.get_profile()
    token = extract_token()
    
    revocation_recorded = False
    if token:
        _, payload = decode_token_unverified(token)
        jti = payload.get("jti") if payload else None
        username = payload.get("sub") if payload else None

        if profile.enforce_revocation:
            revoke_token(token=token, jti=jti, username=username, reason="user_logout")
            revocation_recorded = True

    resp = make_response(
        jsonify({
            "success": True,
            "message": "Logout successful",
            "server_revoked": revocation_recorded,
            "revocation_enforced": profile.enforce_revocation,
        }) if (request.is_json or "application/json" in request.headers.get("Accept", "") or request.headers.get("Authorization")) else redirect(url_for("login_page"))
    )
    # Clear cookie if present
    resp.delete_cookie("session_token", path="/")
    return resp

# --- Mode Switching & Testing Management APIs ---

@app.route("/api/mode", methods=["GET"])
def get_mode():
    return jsonify(AppConfig.get_profile().to_dict())

@app.route("/api/toggle-mode", methods=["POST"])
def toggle_mode():
    current = AppConfig.get_profile().name
    new_mode = "secure" if current == "vulnerable" else "vulnerable"
    profile = AppConfig.set_mode(new_mode)
    return jsonify({
        "success": True,
        "active_mode": profile.name,
        "profile": profile.to_dict()
    })

@app.route("/api/set-mode", methods=["POST"])
def set_mode():
    data = request.get_json(silent=True) or {}
    requested_mode = data.get("mode", "vulnerable")
    profile = AppConfig.set_mode(requested_mode)
    return jsonify({
        "success": True,
        "active_mode": profile.name,
        "profile": profile.to_dict()
    })

@app.route("/api/revoked-tokens", methods=["GET"])
def api_revoked_tokens():
    return jsonify({
        "revoked_tokens": get_revoked_tokens(),
        "revocation_enabled": AppConfig.get_profile().enforce_revocation
    })

@app.route("/api/clear-revoked", methods=["POST"])
def api_clear_revoked():
    clear_revoked_tokens()
    return jsonify({"success": True, "message": "Blacklist cleared"})

@app.route("/api/session-info", methods=["GET"])
def session_info():
    token = extract_token()
    if not token:
        return jsonify({"authenticated": False}), 401
    
    valid, payload, error_msg = validate_session_token(token)
    header, _ = decode_token_unverified(token)
    return jsonify({
        "authenticated": valid,
        "error": error_msg,
        "header": header,
        "payload": payload,
        "profile": AppConfig.get_profile().to_dict()
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
