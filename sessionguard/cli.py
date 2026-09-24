"""
Command Line Interface for SessionGuard.
Provides commands to analyze JWTs, crack HMAC secrets, and decode claims.
"""
import sys
import json
import argparse
from typing import List, Optional

from sessionguard.core.decoder import decode_jwt
from sessionguard.core.cracker import crack_jwt_secret
from sessionguard.scanner import SessionGuardScanner
from sessionguard.reports.console_reporter import render_console_report, BANNER


def handle_analyze(args: argparse.Namespace):
    """Executes full security analysis on a JWT."""
    token_str = args.token.strip()
    target_url = args.target.strip() if args.target else None
    
    scanner = SessionGuardScanner(target_url=target_url, wordlist_path=args.wordlist)
    report = scanner.scan(token_str)
    
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        render_console_report(report)


def handle_crack(args: argparse.Namespace):
    """Executes HMAC secret dictionary attack."""
    print(BANNER)
    token_str = args.token.strip()
    print(f"[*] Starting offline dictionary attack on JWT HMAC secret...")
    if args.wordlist:
        print(f"[*] Using custom wordlist: {args.wordlist}")
    else:
        print(f"[*] Using built-in SessionGuard weak secret wordlist")

    result = crack_jwt_secret(token_str, wordlist_path=args.wordlist)
    
    print("-" * 60)
    print(f"Algorithm         : {result.algorithm}")
    print(f"Keys Tested       : {result.keys_tested}")
    print(f"Elapsed Time      : {result.elapsed_time * 1000:.2f} ms")
    print(f"Cracking Speed    : {int(result.keys_per_second):,} keys/sec")
    print("-" * 60)

    if result.cracked:
        print(f"\033[91m[!] CRITICAL: Secret key successfully cracked!\033[0m")
        print(f"\033[92m[+] Secret Key: '{result.secret}'\033[0m")
        print(f"[*] An attacker can now forge tokens with arbitrary subjects, roles, and expiration times.")
    else:
        print(f"\033[92m[+] Secret was NOT found in the provided wordlist.\033[0m")


def handle_decode(args: argparse.Namespace):
    """Decodes and inspects JWT claims and timestamps."""
    print(BANNER)
    token_str = args.token.strip()
    decoded = decode_jwt(token_str)

    if not decoded.is_valid_format:
        print(f"\033[91m[!] Error: {decoded.error}\033[0m")
        sys.exit(1)

    print(f"\033[96m[*] Header:\033[0m")
    print(json.dumps(decoded.header, indent=2))
    print(f"\n\033[96m[*] Payload Claims:\033[0m")
    print(json.dumps(decoded.payload, indent=2))
    print(f"\n\033[96m[*] Signature:\033[0m")
    print(f"  {decoded.signature[:32]}... ({len(decoded.signature)} chars)")
    print(f"\n\033[96m[*] Timestamp Humanization:\033[0m")
    print(f"  Issued At (iat)    : {decoded.iat_human or 'None'}")
    print(f"  Expires At (exp)   : {decoded.exp_human or 'None (Indefinite)'}")
    print(f"  Remaining Lifetime : {decoded.remaining_lifetime_human}")
    print(f"  Total Lifetime     : {decoded.total_lifetime_human}")


def main(cli_args: Optional[List[str]] = None):
    parser = argparse.ArgumentParser(
        prog="sessionguard",
        description="SessionGuard: A JWT-Based Session Hijacking Risk Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: analyze
    p_analyze = subparsers.add_parser("analyze", help="Run complete security audit against a JWT token")
    p_analyze.add_argument("token", help="The raw JWT string or 'Bearer <token>'")
    p_analyze.add_argument("--target", "-t", help="Target server URL to test active signature bypass (e.g. http://127.0.0.1:5000)")
    p_analyze.add_argument("--wordlist", "-w", help="Custom path to dictionary wordlist for HMAC cracking")
    p_analyze.add_argument("--json", action="store_true", help="Output report as structured JSON")
    p_analyze.set_defaults(func=handle_analyze)

    # Command: crack
    p_crack = subparsers.add_parser("crack", help="Attempt offline dictionary crack of HMAC signing secret")
    p_crack.add_argument("token", help="The raw JWT string")
    p_crack.add_argument("--wordlist", "-w", help="Custom path to dictionary wordlist")
    p_crack.set_defaults(func=handle_crack)

    # Command: decode
    p_decode = subparsers.add_parser("decode", help="Decode and humanize claims in a JWT")
    p_decode.add_argument("token", help="The raw JWT string")
    p_decode.set_defaults(func=handle_decode)

    args = parser.parse_args(cli_args)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
