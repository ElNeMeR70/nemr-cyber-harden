# 🛡️ Nemr Cyber Harden (درع الأمان السيرفري والتصحيح الذاتي)

Autonomous cybersecurity blue-team engine, web server hardener (.htaccess / LiteSpeed / Nginx), AST vulnerability auto-patcher (XSS, SQLi, command injection), and exposed secret/backup scanner.

## 🚀 Capabilities

- **Server Hardening**: Generates military-grade `.htaccess` and LiteSpeed configurations that prevent script execution in uploads, block malicious crawlers, and enforce modern defense headers.
- **AST Auto-Patching**: Automatically identifies and rewrites vulnerable PHP patterns (XSS, weak MD5 password hashes) into secure, modern implementations.
- **Exposed Credentials Scanner**: Traverses directories to catch loose `.env`, backup files, and hardcoded API tokens.

## 📦 Usage

```bash
python cli.py harden-server --dest ./public_html/
python cli.py auto-patch index.php --write
python cli.py scan-secrets ./
```

## 🧪 Testing

```bash
python -m unittest discover -s tests
```
