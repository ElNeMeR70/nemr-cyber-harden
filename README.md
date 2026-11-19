# 🛡️ Nemr Cyber Harden `v3.0.0` (Sovereign Edition)

### *Multi-Stack Server Hardener (`.htaccess`/Nginx/`.user.ini`), AST PHP Vulnerability Auto-Patcher, Supply-Chain Dependency Auditor, Cryptographic CSP Nonce Builder & Live Security Headers Grader*

[![Version](https://img.shields.io/badge/version-3.0.0-crimson.svg?style=for-the-badge)](https://github.com/ElNeMeR70/nemr-cyber-harden/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Security](https://img.shields.io/badge/OWASP-Top%2010%20Blue--Team-emerald.svg?style=for-the-badge)](core/source_patcher.py)
[![Tests](https://img.shields.io/badge/unit%20tests-13%2F13%20passing-brightgreen.svg?style=for-the-badge)](tests/test_cyber_harden.py)
[![License](https://img.shields.io/badge/license-MIT-amber.svg?style=for-the-badge)](LICENSE)

---

## 📖 Executive Overview | نظرة عامة معمّقة

**English:**  
**Nemr Cyber Harden** is a zero-dependency Blue-Team cybersecurity automation suite built for PHP/SaaS hosts, LiteSpeed/Apache/Nginx servers, and CI/CD pipelines. Rather than merely printing generic warnings, it actively generates battle-hardened web server & PHP runtime configs (with zero false-positive query blocking), automatically rewrites vulnerable legacy PHP code (`XSS`, `SQLi`, `extract()`, `md5`, OS command injection) with **unified diffs**, audits `composer.json`/`package.json`/`requirements.txt` for supply-chain compromises, generates **SaaS/Stripe/Paymob** `Content-Security-Policy` headers with PHP 8.3 cryptographic nonce middleware, hunts leaked secrets & PEM keys while auto-generating redacted `.env.example` templates, and grades live production URLs from **`A+` to `F`**.

**بالعربية (الشرح الهندسي الكامل):**  
أداة **`nemr-cyber-harden`** هي منظومة دفاع سيبراني متكاملة (**Blue-Team Engine**) صُممت لتأمين السيرفرات وتطبيقات الويب (خاصة استضافات **LiteSpeed / Apache / Nginx / PHP 8.3**) أوتوماتيكياً بالكامل. الأداة مش بتكتفي بكشف الثغرات، لكنها بتولّد ملفات التحصين المحكمة (`.htaccess` بدون False Positives + `nginx.conf` + `.user.ini` + درع منع تنفيذ PHP داخل مجلد الرفع `/uploads/`)، وتقوم **بترقيع الكود المصاب ذاتياً** (تحويل استعلامات الـ SQL الضعيفة إلى `Prepared Statements`، ومعالجة ثغرات XSS و `extract()` و `md5`) مع عرض الـ Unified Diff، وتدقيق اعتماديات `composer.json` و `package.json` و `requirements.txt` ضد هجمات سلاسل الإمداد، وتوليد سياسات **CSP Nonce Middleware** متوافقة مع **Paymob و Stripe**، وفحص المفاتيح المسربة مع تقييم رؤوس أمان أي رابط حي من **`A+` إلى `F`**.

---

## 🏗️ System Architecture | معمارية النظام

```mermaid
flowchart TB
    SRV[Web Root & PHP Stack] --> HD[ServerHardener]
    HD --> O1[.htaccess + /uploads/ Shield + nginx.hardened.conf + .user.ini]

    PHP[Legacy Vulnerable PHP] --> PAT[SourcePatcher]
    PAT -->|XSS / PDO SQLi / extract / Argon2id / exec| O2[Patched Code + Unified Diff]

    MAN[composer.json / package.json / requirements.txt] --> DEP[DependencyAuditor]
    DEP -->|Unpinned / HTTP URLs / EOL PHP / Install Hooks| O3[Supply-Chain Risk Report]

    PAY[SaaS / Stripe / Paymob Preset] --> CSP[CspBuilder]
    CSP -->|Per-Request random_bytes 16| O4[CSP Header + PHP 8.3 CspNonceMiddleware]

    REPO[Codebase / .env] --> SEC[SecretScanner]
    SEC -->|Entropy + Regex Signatures| O5[Leaked Key Findings + Safe .env.example]

    LIVE[Live HTTPS URL] --> AUD[HeadersAuditor]
    AUD -->|HSTS / CSP / Leaks Penalty| O6[Security Grade A+..F]
```

---

## 🔬 Deep Dive into Core Engines | شرح تفصيلي للمحركات الداخلية

### 1. Supply-Chain Dependency Auditor ([`core/dependency_auditor.py`](core/dependency_auditor.py))
Modern breaches increasingly target package manifests rather than app code. `DependencyAuditor` inspects `composer.json`, `package.json`, and `requirements.txt` locally:
- Flags wildcard or floating branch constraints (`*`, `latest`, `dev-master`) that break deterministic builds.
- Catches insecure plaintext `http://` repository or tarball URLs susceptible to MITM replacement.
- Hunts suspicious `scripts` hooks (`post-install-cmd`, `postinstall`) executing `curl`, `wget`, `eval`, `bash -c`, or encoded PowerShell commands.
- Alerts on End-Of-Life PHP version constraints (`< 8.1`) inside `composer.json`.

### 2. Cryptographic CSP Builder & PHP Nonce Middleware ([`core/csp_builder.py`](core/csp_builder.py))
Crafting strict `Content-Security-Policy` headers without breaking payment gateways is notoriously error-prone. `CspBuilder` provides verified domain allowlists for 4 presets:
- **`strict_api`**: Locks JSON APIs down to `default-src 'none'; frame-ancestors 'none'; base-uri 'none'`.
- **`modern_saas`**: Self-hosted origins + Google Fonts with `object-src 'none'`.
- **`stripe_checkout`**: Explicitly whitelists `js.stripe.com`, `hooks.stripe.com`, and `api.stripe.com`.
- **`paymob_iframe`**: Tailored for Egyptian Accept Paymob iframes (`accept.paymob.com`, `accept.paymobsolutions.com`).
With `--nonce`, emits a drop-in **PHP 8.3 `CspNonceMiddleware`** using cryptographically secure `base64_encode(random_bytes(16))` per-request nonces.

### 3. Automated PHP Vulnerability Patcher + Unified Diff ([`core/source_patcher.py`](core/source_patcher.py))
Auto-rewrites 5 dangerous PHP anti-patterns and outputs clean `difflib.unified_diff` patches:
1. **PDO SQL Injection**: Detects `$stmt = $pdo->query("SELECT ... WHERE email = '" . $_POST['email'] . "'");` and rewrites cleanly to `$stmt = $pdo->prepare("SELECT ... WHERE email = :email"); $stmt->execute([':email' => $_POST['email']]);` — preserving variable assignments without duplicate prefixes!
2. **Reflected XSS**: Wraps bare `echo $_GET[...]` / `$_POST[...]` / `$_REQUEST[...]` in `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')`.
3. **Variable Extraction Overwrite**: Hardens bare `extract($_POST);` using `EXTR_PREFIX_ALL | EXTR_SKIP`.
4. **Obsolete Password Hashing**: Upgrades `md5($user_password)` directly to `password_hash($user_password, PASSWORD_ARGON2ID)`.
5. **Command Injection**: Sanitizes superglobal inputs passed to `shell_exec`, `system`, and `passthru` via `escapeshellcmd()`.

### 4. False-Positive-Free Multi-Stack Server Hardener ([`core/server_hardener.py`](core/server_hardener.py))
- **LiteSpeed / Apache `.htaccess`**: Disables directory listing (`Options -Indexes`), blocks `.env`/`.git`/`.sql`/`.bak` files, enforces security headers, blocks scanner bots (`sqlmap`, `nikto`, `acunetix`), and targets **actual SQLi payloads** (`union+select`, `information_schema`, `benchmark(`, `waitfor delay`, `../`) — fixing the classic naive `(select|set)` false positive that breaks URLs like `?tab=settings` or `?action=select_plan`!
- **Nginx & PHP `.user.ini`**: Emits `nginx.hardened.conf` (`server_tokens off`, upload PHP block) and `.user.ini` (`expose_php = Off`, `session.cookie_httponly = 1`, `session.cookie_samesite = "Strict"`, `allow_url_include = Off`).

### 5. Secret Scanner + `.env.example` Redactor & Live Headers Grader
- **[`core/secret_scanner.py`](core/secret_scanner.py)**: Detects OpenAI/Stripe keys, GitHub PATs, Google Gemini keys (`AIza...`), PEM Private Keys, Slack/Telegram bot tokens, DB DSN strings (`mysql://user:pass@...`), and JWT secrets; computes Shannon entropy and auto-redacts `.env` into `.env.example` (`--redact-env`).
- **[`core/headers_auditor.py`](core/headers_auditor.py)**: Audits live HTTPS URLs (HEAD with GET fallback) or JSON headers, deducting points for missing HSTS/CSP/nosniff/X-Frame-Options/Referrer/Permissions policies and leaking `Server` / `X-Powered-By` headers, assigning **`A+` through `F`**.

---

## 💻 Complete CLI Reference Manual | مرجع الأوامر الكامل

| Command | Arguments & Flags | Purpose |
| :--- | :--- | :--- |
| `harden-server` | `[--dest dir] [--upload-dir dir] [--nginx --domain host] [--php-ini]` | Generate `.htaccess`, upload shield, Nginx & `.user.ini` configs |
| `auto-patch` | `<php_file> [--diff] [--write]` | Auto-patch PHP XSS, PDO SQLi, `extract()`, `md5()`, and `exec` |
| `audit-deps` | `[dir] [--json]` | Audit `composer.json`, `package.json`, `requirements.txt` for supply-chain risks |
| `build-csp` | `--preset strict_api\|modern_saas\|stripe_checkout\|paymob_iframe [--extra-domain URL] [--nonce] [--php-middleware file.php]` | Build strict CSP header or PHP 8.3 Nonce middleware |
| `scan-secrets` | `[dir] [--redact-env .env]` | Scan for keys/PEM/loose dumps or redact `.env` into `.env.example` |
| `audit-headers` | `<url_or_json>` | Grade HTTP response security headers (`A+`–`F`) |
| `--version` | — | Print exact package version (`3.0.0`) |

### Terminal Walkthrough Examples

```bash
# 1. Harden an entire Hostinger / Nginx / PHP 8.3 web root + upload directory
python cli.py harden-server --dest ./public_html --upload-dir ./public_html/uploads --nginx --domain apex.elnemer-ai.com --php-ini

# 2. Preview unified diff & auto-patch vulnerabilities in a legacy PHP endpoint
python cli.py auto-patch legacy_login.php --diff --write

# 3. Generate a Paymob-compatible CSP policy + PHP 8.3 cryptographic Nonce middleware
python cli.py build-csp --preset paymob_iframe --nonce --php-middleware src/Middleware/CspNonceMiddleware.php

# 4. Audit supply-chain dependencies in JSON mode for CI pipelines
python cli.py audit-deps ./my-saas --json

# 5. Scrub a production .env into a safe .env.example template & grade a live domain
python cli.py scan-secrets --redact-env .env
python cli.py audit-headers https://apex.elnemer-ai.com
```

---

## 🐍 Programmatic Python API Usage

```python
from core import ServerHardener, SourcePatcher, DependencyAuditor, CspBuilder, SecretScanner, HeadersAuditor

# 1. Auto-patch legacy PHP code & inspect unified diff
patch_res = SourcePatcher.patch_php_code('<?php $q = $pdo->query("SELECT * FROM users WHERE id = " . $_GET["id"]); ?>')
print(patch_res.diff)

# 2. Audit project dependencies & live URL headers
dep_report = DependencyAuditor.audit_project_dependencies("./my_app")
hdr_grade = HeadersAuditor.audit_url("https://apex.elnemer-ai.com")

# 3. Build Paymob CSP + PHP middleware
csp_php = CspBuilder.generate_php_nonce_middleware(preset="paymob_iframe")
```

---

## 📦 Installation & AI Agent Integration

```bash
git clone https://github.com/ElNeMeR70/nemr-cyber-harden.git
cd nemr-cyber-harden
pip install -e .
nemr-harden --version
```

Copy [`SKILL.md`](SKILL.md) to `~/.gemini/config/skills/nemr-cyber-harden/SKILL.md` for global Antigravity AI agent availability.

---

## 🔐 OWASP & Blue-Team Rule Breakdown | شرح معايير الدفاع والأمان

### Grading Breakdown (`HeadersAuditor` 100-Point Rubric)

| Security Header / Check | Weight | Recommended Production Value | Threat Mitigated |
| :--- | :---: | :--- | :--- |
| `Strict-Transport-Security` | `+20` | `max-age=31536000; includeSubDomains; preload` | SSL-stripping & downgrade MITM |
| `Content-Security-Policy` | `+20` | Strict allowlist + `'nonce-...'` via `CspBuilder` | Stored/Reflected XSS script execution |
| `X-Content-Type-Options` | `+15` | `nosniff` | MIME-confusion drive-by execution |
| `X-Frame-Options` | `+15` | `SAMEORIGIN` | Clickjacking UI redressing |
| `Referrer-Policy` | `+15` | `strict-origin-when-cross-origin` | Leaking sensitive tokens in Referer URLs |
| `Permissions-Policy` | `+15` | `geolocation=(), camera=(), microphone=()` | Unauthorized browser hardware access |
| `X-Powered-By` Present | `-10` | Strip via `expose_php = Off` | Stack fingerprinting (`PHP/8.3.x`) |
| `Server` Version Leak | `-5` | Strip via `ServerSignature Off` / `server_tokens off` | Targeted CVE exploitation |

### Why Precision `.htaccess` SQLi Rules Matter on Shared Hosting (Hostinger LiteSpeed)
Many naive WAF `.htaccess` snippets copy-pasted from blogs contain `(union|select|insert|cast|set|...)` against `QUERY_STRING`. That causes catastrophic false positives on normal app URLs such as `?tab=settings` (`set`) or `?action=select_plan` (`select`)! **Nemr Cyber Harden v3.0.0** uses context-specific patterns (`union(\s|\+)+select`, `information_schema`, `benchmark\s*\(`, `waitfor\s+delay`, `../`) that stop automated scanners (`sqlmap`, `nikto`) without breaking normal user routes.

---

## 📊 Comparison Matrix

| Capability | Manual Checklist | Paid SaaS Scanners | **Nemr Cyber Harden v3.0** |
| :--- | :---: | :---: | :---: |
| False-Positive-Free `.htaccess` + Nginx + `.user.ini` | Manual Copy | ❌ | ✅ Multi-Stack Generator |
| Active PHP Code Auto-Patcher (`SQLi`, `XSS`, `extract`) | ❌ | Reports Only | ✅ Rewrites Code + Unified Diff |
| Multi-Manifest Supply-Chain Audit | Separate CLIs | Paid Tier | ✅ PHP + Node + Python |
| Stripe / Paymob CSP + PHP 8.3 Nonce Middleware | Manual Trial | ❌ | ✅ 1-Command Ready Code |
| Secrets + PEM Key Scanner & `.env.example` Redactor | Manual | ✅ | ✅ Built-in Shannon Entropy |

### Architectural Guarantees & Zero-Regression Patching (ضمانات التعديل الآمن)
1. **Assignment-Preserving SQLi Auto-Patching**: When rewriting `$res = $pdo->query("SELECT ... WHERE id = " . $_GET['id']);`, `SourcePatcher` captures the original `$res =` variable (defaulting to `$stmt` only if unassigned) and generates `$res = $pdo->prepare(...); $res->execute([...]);`, eliminating duplicate assignments and preserving downstream fetch variables.
2. **Constant-Time & Cryptographic Nonces**: Generated `CspNonceMiddleware.php` draws 128 bits of OS CSPRNG entropy via `random_bytes(16)` on every request rather than predictable timestamps or `uniqid()`.
3. **Multi-Pattern Secret Coverage**: Detects OpenAI/Stripe keys, GitHub PATs, AWS Access IDs, Google Gemini API keys, RSA/EC/OpenSSH PEM private keys, Telegram/Slack bot tokens, MySQL/PostgreSQL DSN credentials, and hardcoded JWT signing secrets.

### Directory Structure | هيكل المشروع

```text
nemr-cyber-harden/
├── core/
│   ├── __init__.py                 # Public v3.0.0 exports
│   ├── server_hardener.py          # False-positive-free .htaccess, Nginx, /uploads/ & .user.ini
│   ├── source_patcher.py           # AST PHP patcher (PDO SQLi, XSS, extract, Argon2id, exec)
│   ├── dependency_auditor.py       # Supply-chain scanner (composer, package.json, requirements)
│   ├── csp_builder.py              # Preset CSP policy builder + PHP 8.3 Nonce middleware
│   ├── secret_scanner.py           # Entropy + secret/PEM key scanner & .env.example redactor
│   └── headers_auditor.py          # Live URL security headers auditor (A+..F)
├── tests/
│   └── test_cyber_harden.py        # 13 comprehensive stdlib unit tests
├── cli.py                          # `nemr-harden` CLI entry point (--version 3.0.0)
├── pyproject.toml                  # PEP 621 zero-dependency packaging
├── SKILL.md                        # Antigravity AI agent skill definition
└── LICENSE                         # MIT License
```

---

## 🧪 Verification & Tests

```bash
python -m unittest discover -s tests -v
# Ran 13 tests in 0.020s — OK
```

MIT License — Copyright (c) 2026 [Mahmoud ElNeMeR](https://elnemer-ai.com)
