#!/usr/bin/env python3
"""
Launcher for SessionGuard Web GUI Console.
Runs the interactive cybersecurity analyzer on http://127.0.0.1:5001
"""
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from sessionguard.web.app import app

if __name__ == "__main__":
    print("=" * 70)
    print("  SessionGuard Security Console (Web GUI)")
    print("  URL: http://127.0.0.1:5001")
    print("  Connected Target: http://127.0.0.1:5000")
    print("  Open your browser and navigate to http://127.0.0.1:5001")
    print("=" * 70)
    app.run(host="127.0.0.1", port=5001, debug=False)
