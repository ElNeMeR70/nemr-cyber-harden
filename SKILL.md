---
name: nemr-cyber-harden
description: Autonomous cybersecurity blue-team engine, web server hardener (.htaccess / LiteSpeed / Nginx), AST vulnerability auto-patcher (XSS, SQLi, command injection), and exposed secret/backup scanner. Use when the user asks to secure a website or server, harden .htaccess, fix security vulnerabilities, or scan for leaked secrets.
---

# Nemr Cyber Harden (درع الأمان السيرفري والتصحيح الذاتي)

Autonomous web server defensive hardening, automated AST vulnerability auto-patcher, and exposed credentials scanner.

## Key Capabilities

1. **Defensive Web Server Hardening (`harden-server`)**:
   - Generates comprehensive `.htaccess` configurations blocking scanner bots (sqlmap, nikto), preventing directory listing (`Options -Indexes`), enforcing HSTS, CSP, and X-Frame-Options headers.
   - Generates isolated execution blocks inside upload directories (`/uploads/`) preventing PHP backdoor execution.

2. **Automated Vulnerability Patcher (`auto-patch`)**:
   - Automatically sanitizes reflected XSS by rewriting raw `echo $_GET[...]` into `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')`.
   - Upgrades deprecated `md5()` password hashing to modern `password_hash(..., PASSWORD_ARGON2ID)`.
   - Neutralizes OS command injection vulnerabilities.

3. **Secret & Dangerous File Scanner (`scan-secrets`)**:
   - Discovers loose `.env` files, `.sql` dumps, and hardcoded API tokens (OpenAI, Stripe, GitHub PAT, AWS).

## CLI Quick Reference

```bash
# 1. Harden Web Server & Upload Directory
python cli.py harden-server --dest ./public_html/ --upload-dir ./public_html/uploads/

# 2. Automatically Patch Vulnerabilities in PHP File
python cli.py auto-patch index.php --write

# 3. Scan Entire Codebase for Leaked Secrets
python cli.py scan-secrets ./
```
