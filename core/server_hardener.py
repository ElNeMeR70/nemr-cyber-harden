"""
Nemr Cyber Harden - Server, Nginx & PHP.ini Hardening Engine (v2.0.0)
Generates fortified LiteSpeed/Apache .htaccess, Nginx server configs, and .user.ini/php.ini security directives.
"""

from __future__ import annotations


class ServerHardener:
    """Generates military-grade web server and PHP runtime hardening configurations."""

    @classmethod
    def generate_htaccess(cls, domain: str = "") -> str:
        return """# ========================================================
# NEMR CYBER HARDEN v2.0.0 - HIGH-SECURITY .HTACCESS
# Platform: LiteSpeed Enterprise / Apache 2.4+
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

# 4. ENTERPRISE DEFENSIVE HEADERS
<IfModule mod_headers.c>
    Header set X-Frame-Options "SAMEORIGIN"
    Header set X-Content-Type-Options "nosniff"
    Header set X-XSS-Protection "1; mode=block"
    Header set Referrer-Policy "strict-origin-when-cross-origin"
    Header set Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=()"
    Header set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" env=HTTPS
</IfModule>

# 5. BLOCK SCANNER BOTS & EXPLOIT PAYLOADS (False-Positive Free)
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /

    # Block automated vulnerability scanners
    RewriteCond %{HTTP_USER_AGENT} (acunetix|sqlmap|nikto|havij|nmap|dirbuster|wprecon|jbrofuzz) [NC]
    RewriteRule .* - [F,L]

    # Block active SQLi exploit patterns without false positives on words like 'select_plan' or 'settings'
    RewriteCond %{QUERY_STRING} (union(\\s|\\+)+select|information_schema|benchmark\\s*\\(|sleep\\s*\\(|waitfor\\s+delay) [NC,OR]
    RewriteCond %{QUERY_STRING} base64_encode[^(]*\\([^)]*\\) [NC,OR]
    RewriteCond %{QUERY_STRING} (<|%3C)([^s]*s)+cript.*(>|%3E) [NC,OR]
    RewriteCond %{QUERY_STRING} (\\.\\./|%2e%2e/) [NC]
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

    @classmethod
    def generate_nginx_conf(cls, domain: str = "example.com") -> str:
        """Generates a hardened Nginx server block for PHP / SaaS applications."""
        return f"""# Nemr Cyber Harden v2.0.0 - Hardened Nginx Server Config for {domain}
server {{
    listen 443 ssl http2;
    server_name {domain};
    root /var/www/{domain}/public;
    index index.php index.html;

    server_tokens off;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'self';" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Block hidden dotfiles & sensitive extensions
    location ~ /\\.(env|git|svn|ht) {{
        deny all;
        return 403;
    }}

    location ~* \\.(sql|bak|log|ini|sh|py)$ {{
        deny all;
        return 403;
    }}

    # Prevent PHP execution inside user upload directories
    location ~* ^/uploads/.*\\.(php|phtml|php[3-8])$ {{
        deny all;
        return 403;
    }}

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}
}}
"""

    @classmethod
    def generate_php_ini(cls) -> str:
        """Generates hardened .user.ini / php.ini runtime security directives."""
        return """; Nemr Cyber Harden v2.0.0 - Hardened PHP Runtime Security (.user.ini / php.ini)
expose_php = Off
display_errors = Off
display_startup_errors = Off
log_errors = On

; Strict Cookie & Session Protections
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = "Strict"
session.use_strict_mode = 1
session.use_only_cookies = 1

; Remote file inclusion defense
allow_url_fopen = On
allow_url_include = Off
enable_dl = Off
"""
