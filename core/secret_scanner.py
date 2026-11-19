"""
Nemr Cyber Harden - Secret, Private Key & Shannon Entropy Scanner (v2.0.0)
Finds exposed credentials, PEM private keys, DSN URLs, high-risk files, and generates redacted .env.example templates.
"""

from __future__ import annotations
import math
from pathlib import Path
import re
from typing import Any, Dict, List


class SecretScanner:
    """Scans codebases for exposed secrets, PEM keys, DSN strings, and generates .env.example."""

    PATTERNS = {
        "OPENAI_OR_STRIPE_KEY": re.compile(r"\b(sk-[a-zA-Z0-9]{32,}|sk_live_[a-zA-Z0-9]{24,})\b"),
        "GITHUB_PAT": re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b"),
        "MYSQL_PASSWORD": re.compile(r"(?:DB_PASSWORD|MYSQL_PWD|password)\s*=\s*['\"]([^'\"]{3,})['\"]", re.IGNORECASE),
        "AWS_KEY": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "GOOGLE_GEMINI_KEY": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "PRIVATE_KEY_PEM": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "SLACK_OR_TELEGRAM_TOKEN": re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,}|\d{8,10}:[A-Za-z0-9_-]{35})\b"),
        "DATABASE_URL_DSN": re.compile(r"(?:mysql|postgres|postgresql|mongodb)://[^/\s'\"]+:[^@\s'\"]+@[^\s'\"]+"),
        "JWT_SECRET_ASSIGN": re.compile(r"(?:JWT_SECRET|APP_KEY|HMAC_SECRET)\s*=\s*['\"]?([A-Za-z0-9+/=_-]{16,})['\"]?"),
    }

    DANGEROUS_EXTENSIONS = {".sql", ".bak", ".env", ".dump", ".tar", ".gz"}

    @staticmethod
    def shannon_entropy(s: str) -> float:
        """Computes Shannon entropy (bits per character) to identify high-entropy keys."""
        if not s:
            return 0.0
        counts: Dict[str, int] = {}
        for ch in s:
            counts[ch] = counts.get(ch, 0) + 1
        length = len(s)
        return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 3)

    @classmethod
    def generate_env_example(cls, env_content: str) -> str:
        """Redacts secret values inside a .env file into safe YOUR_<KEY>_HERE placeholders."""
        out_lines: List[str] = []
        sensitive_words = ("KEY", "SECRET", "PASS", "PWD", "TOKEN", "DSN", "URL", "AUTH")

        for line in env_content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in line:
                out_lines.append(line)
                continue

            key, val = line.split("=", 1)
            clean_key = key.strip()
            clean_val = val.strip().strip("'\"")
            is_sensitive = any(w in clean_key.upper() for w in sensitive_words) or cls.shannon_entropy(clean_val) >= 3.5

            if is_sensitive and clean_val:
                out_lines.append(f"{clean_key}=YOUR_{clean_key.upper()}_HERE")
            else:
                out_lines.append(line)

        return "\n".join(out_lines)

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

            if file_path.suffix in cls.DANGEROUS_EXTENSIONS or file_path.name == ".env":
                findings.append({
                    "file": rel_path,
                    "type": "EXPOSED_SENSITIVE_FILE",
                    "severity": "CRITICAL",
                    "details": f"High-risk file '{file_path.name}' should never be placed in a public document root.",
                })

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                for secret_name, regex in cls.PATTERNS.items():
                    matches = regex.findall(content)
                    if matches:
                        findings.append({
                            "file": rel_path,
                            "type": "HARDCODED_SECRET",
                            "severity": "CRITICAL",
                            "details": f"Detected potential secret matching pattern '{secret_name}'",
                        })
            except Exception:
                pass

        return findings
