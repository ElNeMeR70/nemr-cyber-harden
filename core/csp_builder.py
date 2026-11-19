"""
Nemr Cyber Harden - Content-Security-Policy (CSP) Builder & PHP Nonce Middleware Generator (v3.0.0)
Builds tailorable SaaS / Stripe / Paymob CSP policies and emits PHP 8.3 per-request cryptographic nonces.
"""

from __future__ import annotations
from typing import Dict, List, Optional


class CspBuilder:
    """Synthesizes strict Content-Security-Policy strings and PHP 8.3 nonce middleware."""

    PRESETS: Dict[str, Dict[str, List[str]]] = {
        "strict_api": {
            "default-src": ["'none'"],
            "frame-ancestors": ["'none'"],
            "base-uri": ["'none'"],
        },
        "modern_saas": {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            "font-src": ["'self'", "https://fonts.gstatic.com"],
            "img-src": ["'self'", "data:", "https:"],
            "connect-src": ["'self'"],
            "object-src": ["'none'"],
            "frame-ancestors": ["'self'"],
            "base-uri": ["'self'"],
        },
        "stripe_checkout": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://js.stripe.com"],
            "frame-src": ["'self'", "https://js.stripe.com", "https://hooks.stripe.com"],
            "connect-src": ["'self'", "https://api.stripe.com"],
            "img-src": ["'self'", "data:", "https://*.stripe.com"],
            "object-src": ["'none'"],
            "frame-ancestors": ["'self'"],
        },
        "paymob_iframe": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://accept.paymob.com", "https://accept.paymobsolutions.com"],
            "frame-src": ["'self'", "https://accept.paymob.com", "https://accept.paymobsolutions.com"],
            "connect-src": ["'self'", "https://accept.paymob.com"],
            "img-src": ["'self'", "data:", "https:"],
            "object-src": ["'none'"],
            "frame-ancestors": ["'self'"],
        },
    }

    @classmethod
    def build_policy(
        cls,
        preset: str = "modern_saas",
        extra_domains: Optional[List[str]] = None,
        use_nonce: bool = False,
    ) -> str:
        if preset not in cls.PRESETS:
            raise ValueError(f"Unknown CSP preset '{preset}'. Choose from {list(cls.PRESETS.keys())}")

        directives = {k: list(v) for k, v in cls.PRESETS[preset].items()}

        if extra_domains:
            for dname in ("script-src", "connect-src", "frame-src"):
                if dname in directives:
                    for dom in extra_domains:
                        if dom not in directives[dname]:
                            directives[dname].append(dom)

        if use_nonce and "script-src" in directives:
            directives["script-src"].append("'nonce-{NONCE}'")

        return "; ".join(f"{dir_name} {' '.join(vals)}" for dir_name, vals in directives.items()) + ";"

    @classmethod
    def generate_php_nonce_middleware(cls, preset: str = "modern_saas") -> str:
        policy_template = cls.build_policy(preset=preset, use_nonce=True)
        escaped = policy_template.replace("\\", "\\\\").replace("'", "\\'")
        return f"""<?php
declare(strict_types=1);

namespace Nemr\\CyberHarden\\Middleware;

/**
 * Nemr Cyber Harden v3.0.0 - Per-Request Cryptographic CSP Nonce Middleware
 */
class CspNonceMiddleware
{{
    public static function apply(): string
    {{
        $nonce = base64_encode(random_bytes(16));
        $policy = str_replace('{{NONCE}}', $nonce, '{escaped}');

        header('Content-Security-Policy: ' . $policy);
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('Referrer-Policy: strict-origin-when-cross-origin');

        return $nonce;
    }}
}}
"""
