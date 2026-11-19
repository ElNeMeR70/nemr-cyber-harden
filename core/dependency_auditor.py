"""
Nemr Cyber Harden - Software Supply-Chain & Dependency Security Auditor (v3.0.0)
Inspects composer.json, package.json, and requirements.txt for unpinned versions, insecure URLs, malicious scripts, and EOL runtimes.
"""

from __future__ import annotations
import json
from pathlib import Path
import re
from typing import Any, Dict, List


class DependencyAuditor:
    """Audits composer.json, package.json, and requirements.txt for supply-chain risks."""

    UNPINNED_PATTERNS = re.compile(r"^(\*|latest|dev-master|dev-main|x)$", re.IGNORECASE)
    SUSPICIOUS_SCRIPT_RE = re.compile(r"\b(curl|wget|eval|bash\s+-c|powershell\s+-enc|nc\s+-e)\b", re.IGNORECASE)

    @classmethod
    def audit_project_dependencies(cls, directory: str) -> Dict[str, Any]:
        base = Path(directory).resolve()
        findings: List[Dict[str, str]] = []
        manifests_checked: List[str] = []

        # 1. Inspect composer.json (PHP)
        composer_path = base / "composer.json"
        if composer_path.exists():
            manifests_checked.append("composer.json")
            try:
                comp = json.loads(composer_path.read_text(encoding="utf-8", errors="ignore"))
                for section in ("require", "require-dev"):
                    for pkg, ver in comp.get(section, {}).items():
                        v_str = str(ver).strip()
                        if pkg.lower() == "php":
                            m_php = re.search(r"(\d+)\.(\d+)", v_str)
                            if m_php and (int(m_php.group(1)), int(m_php.group(2))) < (8, 1):
                                findings.append({
                                    "manifest": "composer.json",
                                    "severity": "HIGH",
                                    "type": "EOL_PHP_CONSTRAINT",
                                    "detail": f"PHP constraint `{v_str}` allows end-of-life PHP (<8.1).",
                                })
                        elif cls.UNPINNED_PATTERNS.match(v_str) or "dev-" in v_str.lower():
                            findings.append({
                                "manifest": "composer.json",
                                "severity": "HIGH",
                                "type": "UNPINNED_DEPENDENCY",
                                "detail": f"Package `{pkg}` uses unpinned constraint `{v_str}`.",
                            })
                for repo in comp.get("repositories", []):
                    rurl = str(repo.get("url", ""))
                    if rurl.startswith("http://"):
                        findings.append({
                            "manifest": "composer.json",
                            "severity": "CRITICAL",
                            "type": "INSECURE_REGISTRY_URL",
                            "detail": f"Plaintext HTTP repository `{rurl}` enables MITM package tampering.",
                        })
                for hook_name, cmd_val in comp.get("scripts", {}).items():
                    cmd_str = json.dumps(cmd_val)
                    if cls.SUSPICIOUS_SCRIPT_RE.search(cmd_str):
                        findings.append({
                            "manifest": "composer.json",
                            "severity": "CRITICAL",
                            "type": "SUSPICIOUS_INSTALL_HOOK",
                            "detail": f"Script hook `{hook_name}` executes remote download/eval command.",
                        })
            except json.JSONDecodeError:
                findings.append({"manifest": "composer.json", "severity": "MEDIUM", "type": "INVALID_JSON", "detail": "Malformed composer.json"})

        # 2. Inspect package.json (Node/JS)
        pkg_path = base / "package.json"
        if pkg_path.exists():
            manifests_checked.append("package.json")
            try:
                pkg = json.loads(pkg_path.read_text(encoding="utf-8", errors="ignore"))
                for section in ("dependencies", "devDependencies"):
                    for dep, ver in pkg.get(section, {}).items():
                        v_str = str(ver).strip()
                        if cls.UNPINNED_PATTERNS.match(v_str):
                            findings.append({
                                "manifest": "package.json",
                                "severity": "HIGH",
                                "type": "UNPINNED_DEPENDENCY",
                                "detail": f"NPM package `{dep}` uses wildcard/latest `{v_str}`.",
                            })
                        elif v_str.startswith("http://"):
                            findings.append({
                                "manifest": "package.json",
                                "severity": "CRITICAL",
                                "type": "INSECURE_PACKAGE_URL",
                                "detail": f"NPM package `{dep}` resolves over plaintext `{v_str}`.",
                            })
                for script_name, cmd_val in pkg.get("scripts", {}).items():
                    if cls.SUSPICIOUS_SCRIPT_RE.search(str(cmd_val)):
                        findings.append({
                            "manifest": "package.json",
                            "severity": "CRITICAL",
                            "type": "SUSPICIOUS_INSTALL_HOOK",
                            "detail": f"NPM script `{script_name}` contains suspicious shell/download instruction.",
                        })
            except json.JSONDecodeError:
                findings.append({"manifest": "package.json", "severity": "MEDIUM", "type": "INVALID_JSON", "detail": "Malformed package.json"})

        # 3. Inspect requirements.txt (Python)
        req_path = base / "requirements.txt"
        if req_path.exists():
            manifests_checked.append("requirements.txt")
            for raw_line in req_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "http://" in line:
                    findings.append({
                        "manifest": "requirements.txt",
                        "severity": "CRITICAL",
                        "type": "INSECURE_PACKAGE_URL",
                        "detail": f"Dependency line `{line}` fetches over insecure http://.",
                    })
                elif not re.search(r"(==|>=|<=|~=)", line):
                    findings.append({
                        "manifest": "requirements.txt",
                        "severity": "MEDIUM",
                        "type": "UNPINNED_DEPENDENCY",
                        "detail": f"Python requirement `{line}` is unpinned (missing `==` version pin).",
                    })

        return {
            "manifests_checked": manifests_checked,
            "findings_count": len(findings),
            "findings": findings,
            "is_clean": len(findings) == 0,
        }
