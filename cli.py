#!/usr/bin/env python3
"""
Nemr Cyber Harden - Unified CLI
Automated Web Server Hardening, Source Code Vulnerability Auto-Patching, and Secret Audits.
"""

from __future__ import annotations
import argparse
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.server_hardener import ServerHardener
from core.source_patcher import SourcePatcher
from core.secret_scanner import SecretScanner


def cmd_harden(args: argparse.Namespace) -> None:
    dest_dir = Path(args.dest or ".").resolve()
    print(f"\n🛡️ Generating Military-Grade Server Hardening in: {dest_dir}...\n")
    htaccess = ServerHardener.generate_htaccess()
    out_file = dest_dir / ".htaccess"
    out_file.write_text(htaccess, encoding="utf-8")
    print(f"✓ Generated Root Defense: {out_file}")

    if args.upload_dir:
        upload_path = Path(args.upload_dir).resolve()
        upload_path.mkdir(parents=True, exist_ok=True)
        shield_file = upload_path / ".htaccess"
        shield_file.write_text(ServerHardener.generate_upload_dir_shield(), encoding="utf-8")
        print(f"✓ Generated Upload Execution Shield: {shield_file}")

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
    target_dir = Path(args.dir or ".").resolve()
    print(f"\n🔍 Scanning for Exposed Secrets and Dangerous Files in: {target_dir}...\n")
    findings = SecretScanner.scan_directory(str(target_dir))

    if findings:
        print(f"❌ FOUND {len(findings)} SECURITY VULNERABILITIES:")
        for f in findings:
            print(f"  [{f['severity']}] {f['file']}: {f['details']}")
        print("\nTake immediate remediation action to remove exposed secrets.\n")
    else:
        print("✓ No exposed credentials or dangerous files found in scanned directory.\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Nemr Cyber Harden: Autonomous Blue-Team & Zero-Day Patching Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # harden-server
    p_hd = subparsers.add_parser("harden-server", help="Generate defensive .htaccess server rules")
    p_hd.add_argument("--dest", type=str, default=".", help="Target web root folder")
    p_hd.add_argument("--upload-dir", type=str, default=None, help="Optional user upload folder to protect")
    p_hd.set_defaults(func=cmd_harden)

    # auto-patch
    p_pt = subparsers.add_parser("auto-patch", help="Auto-patch XSS, command injection, or weak hashing")
    p_pt.add_argument("file", type=str, help="Source file to patch")
    p_pt.add_argument("--write", action="store_true", help="Write changes directly to file")
    p_pt.set_defaults(func=cmd_patch)

    # scan-secrets
    p_sc = subparsers.add_parser("scan-secrets", help="Scan directory for exposed credentials")
    p_sc.add_argument("dir", type=str, nargs="?", default=".", help="Directory to scan")
    p_sc.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
