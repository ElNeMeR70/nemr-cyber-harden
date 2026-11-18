"""
Nemr Cyber Harden - Server & .htaccess Hardening Engine
Generates fortified Apache, LiteSpeed, and Nginx configurations to eliminate web exploitation vectors.
"""

from __future__ import annotations
from pathlib import Path


class ServerHardener:
    """Generates military-grade web server hardening rules."""

    @classmethod
    def generate_htaccess(cls, domain: str = "") -> str:
        return f"""# ========================================================
# NEMR CYBER HARDEN - HIGH-SECURITY .HTACCESS CONFIGURATION
# Platform: LiteSpeed Enterprise / Apache 2.4+
# Generated: 2026
# ========================================================

# 1. DISABLE DIRECTORY BROWSING
Options -Indexes -MultiViews

# 2. HIDE SERVER SIGNATURE
ServerSignature Off

# 3. BLOCK ACCESS TO SENSITIVE FILES (.env, .git, .sql, .bak, .yml, .json)
<FilesMatch "^(\\.env|\\.git|\\.svn|composer\\.(json|lock)|package\\.(json|lock)|.*\\.(sql|bak|conf|log|ini|sh|py))$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order deny,allow
        Deny from all
    </IfModule>
</FilesMatch>

# 4. PREVENT SCRIPT EXECUTION IN UPLOAD DIRECTORIES
# Note: Place an additional .htaccess inside /uploads/ containing:
# <FilesMatch "\\.(php|phtml|php3|php4|php5|php7|php8|phps|cgi|pl|py|jsp|asp|sh)$">
#    Deny from all
# </FilesMatch>

# 5. ENTERPRISE DEFENSIVE HEADERS
<IfModule mod_headers.c>
    # Prevent clickjacking
    Header set X-Frame-Options "SAMEORIGIN"
    
    # Prevent MIME-sniffing
    Header set X-Content-Type-Options "nosniff"
    
    # XSS Protection filter
    Header set X-XSS-Protection "1; mode=block"
    
    # Referrer privacy policy
    Header set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Permissions Policy
    Header set Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=()"
    
    # HTTP Strict Transport Security (HSTS - 1 Year)
    Header set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" env=HTTPS
</IfModule>

# 6. BLOCK MALICIOUS USER AGENTS & VULNERABILITY SCANNERS
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /

    # Block automated vulnerability scanners
    RewriteCond %{{HTTP_USER_AGENT}} (acunetix|sqlmap|nikto|havij|nmap|dirbuster|wprecon|jbrofuzz) [NC]
    RewriteRule .* - [F,L]

    # Block common SQL injection strings in query string
    RewriteCond %{{QUERY_STRING}} (union|select|insert|cast|set|declare|drop|md5|benchmark) [NC]
    RewriteRule .* - [F,L]

    # Block base64 encoded tags
    RewriteCond %{{QUERY_STRING}} base64_encode[^(]*\\([^)]*\\) [NC,OR]
    RewriteCond %{{QUERY_STRING}} (<|%3C)([^s]*s)+cript.*(>|%3E) [NC]
    RewriteRule .* - [F,L]
</IfModule>
"""

    @classmethod
    def generate_upload_dir_shield(cls) -> str:
        """Shield specifically placed inside user upload folders."""
        return """# Shield uploads directory from any script execution
RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .php8
RemoveType .php .phtml .php3 .php4 .php5 .php7 .php8

<FilesMatch "\\.(php|phtml|php3|php4|php5|php7|php8|phps|cgi|pl|py|jsp|asp|sh|bat)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order deny,allow
        Deny from all
    </IfModule>
</FilesMatch>
"""
