#!/usr/bin/env python3
"""
Nemr Cyber Harden v3.0.0 - Unified CLI (Sovereign Edition)
Hardened .htaccess / Nginx / .user.ini generator, AST PHP SQLi/XSS auto-patcher with unified diff,
Supply-Chain Dependency Auditor, Content-Security-Policy Nonce Builder, Secret Scanner, and Headers Grader.
"""

from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.server_hardener import ServerHardener
from core.source_patcher import SourcePatcher
from core.secret_scanner import SecretScanner
from core.headers_auditor import HeadersAuditor
from core.dependency_auditor import DependencyAuditor
from core.csp_builder import CspBuilder

VERSION = "3.0.0"


def cmd_harden(args: argparse.Namespace) -> None:
    dest_dir = Path(args.dest or ".").resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n🛡️ Generating Military-Grade Server Hardening in: {dest_dir}...\n")

    htaccess = ServerHardener.generate_htaccess()
    out_file = dest_dir / ".htaccess"
    out_file.write_text(htaccess, encoding="utf-8")
    print(f"✓ Generated Root .htaccess Defense: {out_file}")

    if args.upload_dir:
        upload_path = Path(args.upload_dir).resolve()
        upload_path.mkdir(parents=True, exist_ok=True)
        shield_file = upload_path / ".htaccess"
        shield_file.write_text(ServerHardener.generate_upload_dir_shield(), encoding="utf-8")
        print(f"✓ Generated Upload Execution Shield: {shield_file}")

    if args.nginx:
        nginx_file = dest_dir / "nginx.hardened.conf"
        nginx_file.write_text(ServerHardener.generate_nginx_conf(domain=args.domain), encoding="utf-8")
        print(f"✓ Generated Hardened Nginx Config: {nginx_file}")

    if args.php_ini:
        ini_file = dest_dir / ".user.ini"
        ini_file.write_text(ServerHardener.generate_php_ini(), encoding="utf-8")
        print(f"✓ Generated Hardened PHP .user.ini: {ini_file}")

    print("\n✓ Web server defense configured.\n")


def cmd_patch(args: argparse.Namespace) -> None:
    target = Path(args.file).resolve()
    if not target.exists():
        print(f"Error: File {target} not found.")
        sys.exit(1)

    print(f"\n🩹 Running Automated Source Vulnerability Patcher on: {target}...\n")
    source = target.read_text(encoding="utf-8", errors="ignore")
    res = SourcePatcher.patch_php_code(source)

    if res.has_changes:
        print("Patches Applied:")
        for p in res.patches_applied:
            print(f"  ✓ {p}")
        if args.diff and res.diff:
            print("\nUnified Diff:\n" + "-" * 60)
            print(res.diff)
            print("-" * 60)
        if args.write:
            target.write_text(res.patched_code, encoding="utf-8")
            print(f"\n✓ Successfully wrote patched file to: {target}\n")
        else:
            print("\nPreview of Patched Code:\n" + "=" * 60)
            print(res.patched_code[:600])
            print("=" * 60 + "\n(Run with --write to save changes to disk)\n")
    else:
        print("✓ No known patchable vulnerabilities detected in file.\n")


def cmd_scan(args: argparse.Namespace) -> None:
    if args.redact_env:
        env_path = Path(args.redact_env).resolve()
        if not env_path.exists():
            print(f"Error: .env file '{env_path}' not found.")
            sys.exit(1)
        redacted = SecretScanner.generate_env_example(env_path.read_text(encoding="utf-8", errors="ignore"))
        out_example = env_path.parent / ".env.example"
        out_example.write_text(redacted, encoding="utf-8")
        print(f"\n✓ Generated safe redacted template: {out_example}\n")
        print(redacted + "\n")
        return

    target_dir = Path(args.dir or ".").resolve()
    print(f"\n🔍 Scanning for Exposed Secrets, Private Keys, and Dangerous Files in: {target_dir}...\n")
    findings = SecretScanner.scan_directory(str(target_dir))

    if findings:
        print(f"❌ FOUND {len(findings)} SECURITY VULNERABILITIES:")
        for f in findings:
            print(f"  [{f['severity']}] {f['file']}: {f['details']}")
        print("\nTake immediate remediation action to remove exposed secrets.\n")
    else:
        print("✓ No exposed credentials or dangerous files found in scanned directory.\n")


def cmd_audit_headers(args: argparse.Namespace) -> None:
    target = args.target
    if target.startswith(("http://", "https://")):
        report = HeadersAuditor.audit_url(target)
    else:
        path = Path(target)
        raw_headers = json.loads(path.read_text(encoding="utf-8") if path.exists() else target)
        report = HeadersAuditor.audit_headers(raw_headers)

    print(f"\n🛡️ HTTP Security Headers Grade: {report['grade']} ({report['score']}/100)\n" + "=" * 60)
    if report["warnings"]:
        print("Warnings:")
        for w in report["warnings"]:
            print(f"  ⚠️ {w}")
    if report["missing_headers"]:
        print(f"Missing Headers: {', '.join(report['missing_headers'])}")
        for fix in report["recommended_fixes"]:
            print(f"  -> {fix}")
    else:
        print("✓ All critical security headers are present!")
    print("=" * 60 + "\n")


def cmd_audit_deps(args: argparse.Namespace) -> None:
    report = DependencyAuditor.audit_project_dependencies(args.dir)
    if args.json:
        print(json.dumps(report, indent=2))
        return

    print(f"\n📦 Supply-Chain Dependency Audit ({args.dir}):\n" + "=" * 60)
    print(f"Manifests Checked: {report['manifests_checked'] or 'None found'}")
    if report["findings"]:
        for f in report["findings"]:
            print(f"  [{f['severity']}] {f['manifest']} ({f['type']}): {f['detail']}")
    else:
        print("  ✓ 0 supply-chain dependency risks detected.")
    print("=" * 60 + "\n")


def cmd_build_csp(args: argparse.Namespace) -> None:
    policy = CspBuilder.build_policy(
        preset=args.preset,
        extra_domains=args.extra_domain or [],
        use_nonce=args.nonce,
    )
    print(f"\n🔐 Content-Security-Policy ({args.preset}):\n{policy}\n")

    if args.php_middleware:
        php_code = CspBuilder.generate_php_nonce_middleware(preset=args.preset)
        out_p = Path(args.php_middleware)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(php_code, encoding="utf-8")
        print(f"✓ Generated PHP 8.3 Nonce Middleware: {out_p}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Nemr Cyber Harden v3.0.0: Sovereign Blue-Team & Hardening Engine")
    parser.add_argument("--version", action="version", version=VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_hd = subparsers.add_parser("harden-server", help="Generate defensive .htaccess, Nginx, or PHP .user.ini rules")
    p_hd.add_argument("--dest", type=str, default=".", help="Target web root folder")
    p_hd.add_argument("--upload-dir", type=str, default=None, help="Optional user upload folder to protect")
    p_hd.add_argument("--nginx", action="store_true", help="Also generate nginx.hardened.conf")
    p_hd.add_argument("--domain", type=str, default="example.com", help="Domain name for Nginx server block")
    p_hd.add_argument("--php-ini", action="store_true", help="Also generate hardened .user.ini")
    p_hd.set_defaults(func=cmd_harden)

    p_pt = subparsers.add_parser("auto-patch", help="Auto-patch XSS, SQLi PDO, extract(), exec, or md5")
    p_pt.add_argument("file", type=str, help="Source file to patch")
    p_pt.add_argument("--write", action="store_true", help="Write changes directly to file")
    p_pt.add_argument("--diff", action="store_true", help="Print unified diff")
    p_pt.set_defaults(func=cmd_patch)

    p_sc = subparsers.add_parser("scan-secrets", help="Scan directory for secrets or generate redacted .env.example")
    p_sc.add_argument("dir", type=str, nargs="?", default=".", help="Directory to scan")
    p_sc.add_argument("--redact-env", type=str, default=None, help="Generate .env.example from a .env file")
    p_sc.set_defaults(func=cmd_scan)

    p_hdr = subparsers.add_parser("audit-headers", help="Audit HTTP response security headers (A+..F)")
    p_hdr.add_argument("target", type=str, help="Live URL (https://...) or JSON headers string/file")
    p_hdr.set_defaults(func=cmd_audit_headers)

    p_dep = subparsers.add_parser("audit-deps", help="Audit composer.json, package.json, and requirements.txt")
    p_dep.add_argument("dir", type=str, nargs="?", default=".", help="Project root directory")
    p_dep.add_argument("--json", action="store_true", help="Emit JSON output")
    p_dep.set_defaults(func=cmd_audit_deps)

    p_csp = subparsers.add_parser("build-csp", help="Generate tailored CSP header or PHP 8.3 Nonce middleware")
    p_csp.add_argument("--preset", type=str, default="modern_saas", choices=list(CspBuilder.PRESETS.keys()), help="CSP preset")
    p_csp.add_argument("--extra-domain", action="append", default=None, help="Additional allowed HTTPS origin")
    p_csp.add_argument("--nonce", action="store_true", help="Inject 'nonce-{NONCE}' into script-src")
    p_csp.add_argument("--php-middleware", type=str, default=None, help="Output PHP 8.3 CspNonceMiddleware.php path")
    p_csp.set_defaults(func=cmd_build_csp)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
