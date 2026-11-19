"""
Nemr Cyber Harden - Live HTTP Security Headers Auditor (v2.0.0)
Scores HTTP response headers against OWASP hardening baselines and flags Server/X-Powered-By leaks.
"""

from __future__ import annotations
from typing import Any, Dict, List
import urllib.error
import urllib.request


class HeadersAuditor:
    """Audits HTTP security headers from live URLs or dictionaries and computes A+..F grades."""

    REQUIRED_HEADERS = {
        "strict-transport-security": (20, "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`."),
        "content-security-policy": (20, "Define a restrictive `Content-Security-Policy` (`default-src 'self'`)."),
        "x-content-type-options": (15, "Set `X-Content-Type-Options: nosniff`."),
        "x-frame-options": (15, "Set `X-Frame-Options: SAMEORIGIN` or `DENY`."),
        "referrer-policy": (15, "Set `Referrer-Policy: strict-origin-when-cross-origin`."),
        "permissions-policy": (15, "Set `Permissions-Policy: geolocation=(), camera=(), microphone=()`."),
    }

    @classmethod
    def audit_headers(cls, headers: Dict[str, str]) -> Dict[str, Any]:
        lower_map = {k.lower(): v for k, v in headers.items()}
        score = 0
        missing: List[str] = []
        warnings: List[str] = []
        recommended_fixes: List[str] = []

        for hname, (points, fix_hint) in cls.REQUIRED_HEADERS.items():
            if hname in lower_map and str(lower_map[hname]).strip():
                score += points
            else:
                missing.append(hname)
                recommended_fixes.append(fix_hint)

        # Penalize technology / version leakage
        powered_by = lower_map.get("x-powered-by", "")
        if powered_by:
            score = max(0, score - 10)
            warnings.append(f"`X-Powered-By: {powered_by}` leaks backend runtime stack. Set `expose_php = Off`.")

        server_hdr = lower_map.get("server", "")
        if "/" in server_hdr and any(ch.isdigit() for ch in server_hdr):
            score = max(0, score - 5)
            warnings.append(f"`Server: {server_hdr}` exposes version details. Set `ServerSignature Off` / `server_tokens off`.")

        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 30:
            grade = "D"
        else:
            grade = "F"

        return {
            "score": score,
            "grade": grade,
            "missing_headers": missing,
            "warnings": warnings,
            "recommended_fixes": recommended_fixes,
        }

    @classmethod
    def audit_url(cls, url: str, timeout: int = 10) -> Dict[str, Any]:
        """Fetches live HTTP headers via HEAD (with GET fallback) and returns security grade."""
        req = urllib.request.Request(url, method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                hdrs = dict(resp.headers.items())
                result = cls.audit_headers(hdrs)
                result["url"] = url
                result["status_code"] = resp.status
                return result
        except urllib.error.HTTPError as e:
            if e.code == 405:
                req_get = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req_get, timeout=timeout) as resp:
                    hdrs = dict(resp.headers.items())
                    result = cls.audit_headers(hdrs)
                    result["url"] = url
                    result["status_code"] = resp.status
                    return result
            result = cls.audit_headers(dict(e.headers.items()) if e.headers else {})
            result["url"] = url
            result["status_code"] = e.code
            return result
