"""
Colorized Terminal Reporter for SessionGuard.
Renders professional security assessment reports for terminal presentation.
"""
import sys
from colorama import Fore, Back, Style, init
from sessionguard.core.risk_engine import AuditReport

# Initialize colorama for cross-platform ANSI support
init(autoreset=True)


BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}================================================================================
   ____                      _               ____                         _ 
  / ___|   ___  ___ ___ (_) ___  _ __   / ___|_   _   __ _ _ __ __| |
  \\___ \\  / _ \\/ __/ __| | |/ _ \\| '_ \\ | |  _| | | | / _` | '__/ _` |
   ___) ||  __/\\__ \\__ \\ | | (_) | | | || |_| | |_| || (_| | | | (_| |
  |____/  \\___||___/___/_|_|\\___/|_| |_| \\____|\\__,_| \\__,_|_|  \\__,_|
{Fore.LIGHTBLACK_EX}  v1.0.0 | JWT Session Hijacking Risk Assessment Tool | OWASP ASVS V3 / A07:2021
================================================================================{Style.RESET_ALL}
"""


def _severity_color(severity: str) -> str:
    s = severity.upper()
    if s == "CRITICAL":
        return Fore.RED + Style.BRIGHT
    if s == "HIGH":
        return Fore.LIGHTRED_EX + Style.BRIGHT
    if s == "MEDIUM":
        return Fore.YELLOW + Style.BRIGHT
    if s == "LOW":
        return Fore.GREEN
    return Fore.CYAN


def _score_badge(score: int) -> str:
    if score >= 9:
        return f"{Fore.WHITE}{Back.RED}{Style.BRIGHT} [CRITICAL 9/9] {Style.RESET_ALL}"
    if score >= 6:
        return f"{Fore.BLACK}{Back.LIGHTRED_EX}{Style.BRIGHT} [HIGH {score}/9] {Style.RESET_ALL}"
    if score >= 4:
        return f"{Fore.BLACK}{Back.YELLOW}{Style.BRIGHT} [MEDIUM {score}/9] {Style.RESET_ALL}"
    return f"{Fore.BLACK}{Back.GREEN}{Style.BRIGHT} [LOW {score}/9] {Style.RESET_ALL}"


def render_console_report(report: AuditReport):
    """Prints a structured, formatted security assessment to stdout."""
    print(BANNER)

    # 1. TOKEN SUMMARY SECTION
    meta = report.token_metadata
    print(f"{Fore.CYAN}{Style.BRIGHT}[+] TOKEN INSPECTION & METADATA{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}{'-' * 80}{Style.RESET_ALL}")
    print(f"  Token Preview   : {Fore.WHITE}{report.raw_token_preview}{Style.RESET_ALL}")
    print(f"  Algorithm (alg) : {Fore.YELLOW if meta.get('algorithm') == 'none' else Fore.GREEN}{meta.get('algorithm')}{Style.RESET_ALL} ({meta.get('type')})")
    print(f"  Subject (sub)   : {Fore.WHITE}{meta.get('subject')}{Style.RESET_ALL}  |  Role: {Fore.WHITE}{meta.get('role')}{Style.RESET_ALL}")
    print(f"  Issued At (iat) : {Fore.WHITE}{meta.get('issued_at')}{Style.RESET_ALL}")
    print(f"  Expires (exp)   : {Fore.WHITE}{meta.get('expires_at')}{Style.RESET_ALL}")
    print(f"  Total Lifetime  : {Fore.WHITE}{meta.get('total_lifetime')}{Style.RESET_ALL}")
    print(f"  Status          : {meta.get('remaining_time')}")
    print(f"{Fore.LIGHTBLACK_EX}{'-' * 80}{Style.RESET_ALL}\n")

    # 2. CHECKS AUDIT TABLE
    print(f"{Fore.CYAN}{Style.BRIGHT}[+] SECURITY CHECKS EVALUATION MATRIX{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}{'=' * 80}{Style.RESET_ALL}")
    print(f"{'STATUS':<8} | {'CHECK NAME':<30} | {'SEVERITY':<10} | {'SCORE':<7} | {'CWE':<20}")
    print(f"{Fore.LIGHTBLACK_EX}{'-' * 80}{Style.RESET_ALL}")

    for r in report.check_results:
        if r.passed:
            status_str = f"{Fore.GREEN}{Style.BRIGHT}[PASS]{Style.RESET_ALL}"
        else:
            status_str = f"{Fore.RED}{Style.BRIGHT}[FAIL]{Style.RESET_ALL}"
            
        sev_color = _severity_color(r.severity)
        sev_str = f"{sev_color}{r.severity:<10}{Style.RESET_ALL}"
        score_str = f"{r.score}/9"
        cwe_short = r.cwe.split(":")[0] if ":" in r.cwe else r.cwe[:18]

        print(f"{status_str:<17} | {r.name:<30} | {sev_str:<19} | {score_str:<7} | {cwe_short:<20}")

    print(f"{Fore.LIGHTBLACK_EX}{'=' * 80}{Style.RESET_ALL}\n")

    # 3. DETAILED FINDINGS & REMEDIATION
    failed = [r for r in report.check_results if not r.passed]
    if failed:
        print(f"{Fore.RED}{Style.BRIGHT}[!] VULNERABILITY FINDINGS & HIJACKING RISKS{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}{'-' * 80}{Style.RESET_ALL}")
        for i, r in enumerate(failed, 1):
            sev_col = _severity_color(r.severity)
            print(f"  {Fore.WHITE}{Style.BRIGHT}Finding #{i}: {sev_col}{r.title}{Style.RESET_ALL}")
            print(f"  {Fore.LIGHTBLACK_EX}Standards     :{Style.RESET_ALL} {r.cwe} | {r.owasp}")
            print(f"  {Fore.LIGHTBLACK_EX}Risk Score    :{Style.RESET_ALL} Exploitability={r.exploitability}/3, Impact={r.impact}/3 -> Total={r.score}/9")
            print(f"  {Fore.LIGHTBLACK_EX}Analysis      :{Style.RESET_ALL} {r.description}")
            if r.remediation:
                print(f"  {Fore.GREEN}{Style.BRIGHT}Remediation   :{Style.RESET_ALL} {r.remediation}")
            print(f"{Fore.LIGHTBLACK_EX}{'-' * 80}{Style.RESET_ALL}")
        print()

    # 4. OVERALL EXECUTIVE RISK VERDICT
    print(f"{Fore.CYAN}{Style.BRIGHT}[+] EXECUTIVE RISK ASSESSMENT & VERDICT{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}{'=' * 80}{Style.RESET_ALL}")
    badge = _score_badge(report.overall_score)
    print(f"  OVERALL ASSESSMENT : {badge}")
    print(f"  CHECKS SUMMARY     : {Fore.GREEN}{report.passed_count} Passed{Style.RESET_ALL}, {Fore.RED if report.failed_count > 0 else Fore.GREEN}{report.failed_count} Failed{Style.RESET_ALL} (Total: {report.total_checks})")
    print()
    print(f"  {Fore.WHITE}{Style.BRIGHT}HIJACKING RISK VERDICT:{Style.RESET_ALL}")
    print(f"  {Fore.LIGHTYELLOW_EX}{report.hijack_verdict}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}{'=' * 80}{Style.RESET_ALL}\n")
