"""
Nemr Cyber Harden - Automated Source Code Patcher
Scans source files and automatically rewrites vulnerable patterns into secure forms.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass
class PatchResult:
    original_code: str
    patched_code: str
    patches_applied: List[str]
    has_changes: bool


class SourcePatcher:
    """Safely patches common OWASP Top 10 vulnerabilities in source files."""

    @classmethod
    def patch_php_code(cls, source: str) -> PatchResult:
        patched = source
        applied: List[str] = []

        # 1. Patch Reflected XSS: echo $_GET['x'] -> echo htmlspecialchars($_GET['x'], ENT_QUOTES, 'UTF-8')
        xss_pattern = re.compile(r"echo\s+(\$_(?:GET|POST|REQUEST)\[['\"][a-zA-Z0-9_]+['\"]\])\s*;")
        for match in xss_pattern.finditer(source):
            raw_expr = match.group(1)
            repl = f"echo htmlspecialchars({raw_expr}, ENT_QUOTES, 'UTF-8');"
            patched = patched.replace(match.group(0), repl)
            applied.append(f"Wrapped raw input {raw_expr} with htmlspecialchars(..., ENT_QUOTES, 'UTF-8')")

        # 2. Patch MD5 password hashing
        md5_pass_pattern = re.compile(r"\bmd5\s*\(\s*(\$[a-zA-Z0-9_]*password[a-zA-Z0-9_]*)\s*\)", re.IGNORECASE)
        for match in md5_pass_pattern.finditer(source):
            pass_var = match.group(1)
            repl = f"password_hash({pass_var}, PASSWORD_ARGON2ID)"
            patched = patched.replace(match.group(0), repl)
            applied.append(f"Upgraded obsolete md5({pass_var}) to password_hash(..., PASSWORD_ARGON2ID)")

        # 3. Patch raw exec/system calls
        shell_pattern = re.compile(r"\b(shell_exec|system|passthru)\s*\(\s*(\$_(?:GET|POST|REQUEST)\[[^\]]+\])\s*\)")
        for match in shell_pattern.finditer(source):
            fn = match.group(1)
            raw = match.group(2)
            repl = f"{fn}(escapeshellcmd({raw}))"
            patched = patched.replace(match.group(0), repl)
            applied.append(f"Secured command injection in {fn}() with escapeshellcmd()")

        return PatchResult(
            original_code=source,
            patched_code=patched,
            patches_applied=applied,
            has_changes=len(applied) > 0
        )
