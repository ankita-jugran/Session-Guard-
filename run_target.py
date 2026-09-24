#!/usr/bin/env python3
"""
Launcher for Dummy Login App (SessionGuard Target).
Runs Flask development server on http://127.0.0.1:5000
"""
import sys
import os

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.app import app

if __name__ == "__main__":
    print("=" * 65)
    print("  SessionGuard Test Target App (Part A)")
    print("  URL: http://127.0.0.1:5000")
    print("  Test Accounts: alice:password123 | bob:secretPass! | admin:admin2026")
    print("  Toggle Mode at: http://127.0.0.1:5000 or via POST /api/toggle-mode")
    print("=" * 65)
    app.run(host="127.0.0.1", port=5000, debug=False)
