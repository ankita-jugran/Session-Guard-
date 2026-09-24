"""
SessionGuard Web GUI Application.
Runs an interactive security analysis console on port 5001.
"""
import os
import sys
import time
import requests
import jwt
from flask import Flask, render_template, request, jsonify

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from sessionguard.scanner import SessionGuardScanner
from sessionguard.core.cracker import crack_jwt_secret
from sessionguard.core.decoder import decode_jwt

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static")
)
app.secret_key = "sessionguard_web_analyzer_local_secret"


@app.route("/")
def index():
    """Renders the main SessionGuard interactive security console."""
    return render_template("index.html")

@app.route("/report")
def report():
    """Renders the dedicated, printable PDF-friendly report page."""
    return render_template("report.html")


@app.route("/api/target-status", methods=["GET"])
def target_status():
    """Checks whether the target application host is reachable."""
    target_url = request.args.get("target_url", "http://127.0.0.1:5000").rstrip("/")
    try:
        resp = requests.get(target_url, timeout=1.5, allow_redirects=True)
        # Any response indicates the web server is online
        return jsonify({
            "online": True,
            "target_url": target_url
        })
    except Exception:
        pass

    return jsonify({
        "online": False,
        "target_url": target_url
    })


@app.route("/api/scan", methods=["POST"])
def scan_token():
    """Executes full security analysis on a provided JWT string."""
    data = request.get_json(silent=True) or {}
    raw_token = data.get("token", "").strip()
    target_url = data.get("target_url", "").strip() or None

    if not raw_token:
        return jsonify({"error": "No JWT token provided for analysis."}), 400

    try:
        scanner = SessionGuardScanner(target_url=target_url)
        report = scanner.scan(raw_token)
        return jsonify({
            "success": True,
            "report": report.to_dict()
        })
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route("/api/crack", methods=["POST"])
def crack_token():
    """Runs a standalone dictionary attack against HMAC signature."""
    data = request.get_json(silent=True) or {}
    raw_token = data.get("token", "").strip()

    if not raw_token:
        return jsonify({"error": "No JWT token provided."}), 400

    result = crack_jwt_secret(raw_token)
    return jsonify({
        "cracked": result.cracked,
        "secret": result.secret,
        "algorithm": result.algorithm,
        "keys_tested": result.keys_tested,
        "elapsed_ms": round(result.elapsed_time * 1000, 2),
        "keys_per_second": int(result.keys_per_second)
    })
