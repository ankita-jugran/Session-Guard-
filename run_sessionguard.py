"""
Entry point for SessionGuard CLI tool.
Usage:
    python run_sessionguard.py analyze <token> [--target <url>]
    python run_sessionguard.py crack <token>
    python run_sessionguard.py decode <token>
"""
import sys
from sessionguard.cli import main

if __name__ == "__main__":
    main()
