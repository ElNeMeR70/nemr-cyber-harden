#!/usr/bin/env python3
"""Unit tests for Nemr Cyber Harden."""

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


if __name__ == "__main__":
    unittest.main()
