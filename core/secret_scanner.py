"""
Nemr Cyber Harden - Secret & Sensitive File Scanner
Finds exposed credentials, misplaced .env files, database backups, and uncommitted secrets.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import Dict, List, Any


class SecretScanner:
    """Scans projects for exposed secrets and high-risk sensitive files."""

    PATTERNS = {
        "OPENAI_OR_STRIPE_KEY": re.compile(r"\b(sk-[a-zA-Z0-9]{32,}|sk_live_[a-zA-Z0-9]{24,})\b"),
        "GITHUB_PAT": re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b"),
        "MYSQL_PASSWORD": re.compile(r"(?:DB_PASSWORD|MYSQL_PWD|password)\s*=\s*['\"]([^'\"]{3,})['\"]", re.IGNORECASE),
        "AWS_KEY": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    }

    DANGEROUS_EXTENSIONS = {".sql", ".bak", ".env", ".dump", ".tar", ".gz"}

    @classmethod
    def scan_directory(cls, directory_path: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        base = Path(directory_path).resolve()

        if not base.exists():
            return findings

        for file_path in base.rglob("*"):
            if not file_path.is_file():
                continue
            if ".git" in file_path.parts:
                continue

            rel_path = str(file_path.relative_to(base))

            # Check for loose dangerous files in web directories
            if file_path.suffix in cls.DANGEROUS_EXTENSIONS or file_path.name == ".env":
                findings.append({
                    "file": rel_path,
                    "type": "EXPOSED_SENSITIVE_FILE",
                    "severity": "CRITICAL",
                    "details": f"High-risk file '{file_path.name}' should never be placed in a public document root."
                })

            # Check content for secrets
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                for secret_name, regex in cls.PATTERNS.items():
                    matches = regex.findall(content)
                    if matches:
                        findings.append({
                            "file": rel_path,
                            "type": "HARDCODED_SECRET",
                            "severity": "CRITICAL",
                            "details": f"Detected potential secret matching pattern '{secret_name}'"
                        })
            except Exception:
                pass

        return findings
