"""
Nemr Cyber Harden - Automated Source Code Patcher & Unified Diff Engine (v2.0.0)
Auto-patches XSS, MD5 passwords, shell injection, PDO SQLi concatenations, and bare extract() calls.
"""

from __future__ import annotations
from dataclasses import dataclass
import difflib
import re
from typing import List


@dataclass
class PatchResult:
    original_code: str
    patched_code: str
    patches_applied: List[str]
    has_changes: bool
    diff: str = ""


class SourcePatcher:
    """Safely patches OWASP Top 10 vulnerabilities in PHP source files with unified diff output."""

    @classmethod
    def patch_php_code(cls, source: str) -> PatchResult:
        patched = source
        applied: List[str] = []

        # 1. Patch Reflected XSS: echo $_GET['x'];
        xss_pattern = re.compile(r"echo\s+(\$_(?:GET|POST|REQUEST)\[['\"][a-zA-Z0-9_]+['\"]\])\s*;")
        for match in xss_pattern.finditer(patched):
            raw_expr = match.group(1)
            repl = f"echo htmlspecialchars({raw_expr}, ENT_QUOTES, 'UTF-8');"
            patched = patched.replace(match.group(0), repl)
            applied.append(f"Wrapped raw input {raw_expr} with htmlspecialchars(..., ENT_QUOTES, 'UTF-8')")

        # 2. Patch MD5 password hashing
        md5_pass_pattern = re.compile(r"\bmd5\s*\(\s*(\$[a-zA-Z0-9_]*password[a-zA-Z0-9_]*)\s*\)", re.IGNORECASE)
        for match in md5_pass_pattern.finditer(patched):
            pass_var = match.group(1)
            repl = f"password_hash({pass_var}, PASSWORD_ARGON2ID)"
            patched = patched.replace(match.group(0), repl)
            applied.append(f"Upgraded obsolete md5({pass_var}) to password_hash(..., PASSWORD_ARGON2ID)")

        # 3. Patch raw exec/system calls
        shell_pattern = re.compile(r"\b(shell_exec|system|passthru)\s*\(\s*(\$_(?:GET|POST|REQUEST)\[[^\]]+\])\s*\)")
        for match in shell_pattern.finditer(patched):
            fn = match.group(1)
            raw = match.group(2)
            repl = f"{fn}(escapeshellcmd({raw}))"
            patched = patched.replace(match.group(0), repl)
            applied.append(f"Secured command injection in {fn}() with escapeshellcmd()")

        # 4. Patch PDO SQL Injection concatenations:
        #    [$var = ]$pdo->query("SELECT ... WHERE col = " . $_GET['key'])
        #    [$var = ]$pdo->query("SELECT ... WHERE col = '" . $_POST['key'] . "'")
        sqli_quoted_pattern = re.compile(
            r"(?:\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*)?(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*->\s*query\s*\(\s*\"([^\"]*?=\s*)'\"\s*\.\s*(\$_(?:GET|POST|REQUEST)\[['\"]([a-zA-Z0-9_]+)['\"]\])\s*\.\s*\"'([^\"]*)\"\s*\)\s*;",
            re.IGNORECASE,
        )
        for match in list(sqli_quoted_pattern.finditer(patched)):
            stmt_var = f"${match.group(1)}" if match.group(1) else "$stmt"
            pdo_var = match.group(2)
            prefix_sql = match.group(3)
            superglobal = match.group(4)
            key = match.group(5)
            suffix_sql = match.group(6)
            new_stmt = (
                f'{stmt_var} = {pdo_var}->prepare("{prefix_sql}:{key}{suffix_sql}"); '
                f"{stmt_var}->execute([':{key}' => {superglobal}]);"
            )
            patched = patched.replace(match.group(0), new_stmt)
            applied.append(f"Converted raw quoted SQLi in {pdo_var}->query() into prepared statement (:{key})")

        sqli_unquoted_pattern = re.compile(
            r"(?:\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*)?(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*->\s*query\s*\(\s*\"([^\"]*?=\s*)\"\s*\.\s*(\$_(?:GET|POST|REQUEST)\[['\"]([a-zA-Z0-9_]+)['\"]\])\s*\)\s*;",
            re.IGNORECASE,
        )
        for match in list(sqli_unquoted_pattern.finditer(patched)):
            stmt_var = f"${match.group(1)}" if match.group(1) else "$stmt"
            pdo_var = match.group(2)
            prefix_sql = match.group(3)
            superglobal = match.group(4)
            key = match.group(5)
            new_stmt = (
                f'{stmt_var} = {pdo_var}->prepare("{prefix_sql}:{key}"); '
                f"{stmt_var}->execute([':{key}' => {superglobal}]);"
            )
            patched = patched.replace(match.group(0), new_stmt)
            applied.append(f"Converted raw SQLi concatenation in {pdo_var}->query() into prepared statement (:{key})")

        # 5. Patch dangerous bare extract($_GET|$_POST|$_REQUEST);
        extract_pattern = re.compile(r"\bextract\s*\(\s*(\$_(?:GET|POST|REQUEST))\s*\)\s*;")
        for match in list(extract_pattern.finditer(patched)):
            sg = match.group(1)
            repl = f"extract({sg}, EXTR_PREFIX_ALL | EXTR_SKIP, 'req');"
            patched = patched.replace(match.group(0), repl)
            applied.append(f"Hardened bare extract({sg}) with EXTR_PREFIX_ALL | EXTR_SKIP")

        diff_text = ""
        if patched != source:
            diff_lines = difflib.unified_diff(
                source.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile="before.php",
                tofile="after.php",
            )
            diff_text = "".join(diff_lines)

        return PatchResult(
            original_code=source,
            patched_code=patched,
            patches_applied=applied,
            has_changes=len(applied) > 0,
            diff=diff_text,
        )
