---
name: nemr-cyber-harden
description: Autonomous cybersecurity blue-team suite v3.0.0: LiteSpeed/Apache .htaccess, Nginx, and PHP .user.ini hardener, AST PHP auto-patcher (XSS, PDO SQLi, extract(), md5, shell_exec) with unified diff, supply-chain dependency auditor (composer.json, package.json, requirements.txt), CSP builder & PHP nonce middleware generator, secret & PEM scanner with .env.example redactor, and live HTTP security headers grader (A+..F). Use when hardening servers, patching PHP, auditing dependencies, generating CSPs, or grading HTTP headers.
---

# Nemr Cyber Harden v3.0.0 (درع الأمان السيرفري وتدقيق الاعتماديات والـ CSP)

Autonomous server/Nginx/PHP hardener, AST PHP SQLi/XSS auto-patcher, supply-chain manifest auditor, cryptographic CSP nonce middleware generator, secret/PEM scanner, and live HTTP headers grader.

## Key Capabilities

1. **Supply-Chain Dependency Auditor (`audit-deps`)**:
   - Scans `composer.json`, `package.json`, and `requirements.txt` for unpinned `*`/`latest`/`dev-` dependencies, insecure `http://` registry URLs, suspicious install script hooks (`curl`/`eval`/`powershell`), and EOL PHP (`<8.1`).
2. **CSP Builder & PHP 8.3 Nonce Middleware (`build-csp`)**:
   - Generates tailored `Content-Security-Policy` policies (`strict_api`, `modern_saas`, `stripe_checkout`, `paymob_iframe`) and emits PHP 8.3 per-request `random_bytes(16)` nonce middleware.
3. **Multi-Stack Server Hardening (`harden-server`)**:
   - Produces false-positive-free `.htaccess`, hardened Nginx server blocks, PHP `.user.ini`, and `/uploads/` execution shields.
4. **AST PHP Auto-Patcher, Secret Scanner & Headers Grader (`auto-patch`, `scan-secrets`, `audit-headers`)**:
   - Rewrites PDO SQLi concatenations into prepared statements cleanly, catches PEM/Gemini/API keys + generates `.env.example`, and grades live URLs `A+`–`F`.

## CLI Quick Reference

```bash
python cli.py --version
python cli.py audit-deps ./project --json
python cli.py build-csp --preset paymob_iframe --nonce --php-middleware CspNonceMiddleware.php
python cli.py harden-server --dest ./public_html/ --upload-dir ./public_html/uploads/ --nginx --domain apex.elnemer-ai.com --php-ini
python cli.py auto-patch legacy.php --diff --write
python cli.py scan-secrets ./ --redact-env .env
python cli.py audit-headers https://apex.elnemer-ai.com
```
