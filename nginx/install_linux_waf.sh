#!/usr/bin/env bash
# ==============================================================================
# Linux CN-Server VM: Nginx + ModSecurity & OWASP CRS Setup Script
# Ubuntu 22.04 / 24.04 LTS Compatible
# ==============================================================================
set -euo pipefail

echo "======================================================================"
echo "[+] Mini Enterprise: Secure Portal WAF Installation"
echo "    Target: Linux CN-Server VM (Reverse-Proxy WAF Layer)"
echo "======================================================================"

if [[ $EUID -ne 0 ]]; then
   echo "[-] Error: This installation script must be run as root (or with sudo)."
   exit 1
fi

# 1. Install prerequisites
echo "[1/6] Updating package cache and installing Nginx + ModSecurity..."
apt-get update -qq
apt-get install -y -qq \
    nginx \
    libnginx-mod-http-modsecurity \
    modsecurity-crs \
    git \
    curl

# 2. Create ModSecurity configuration directory
echo "[2/6] Configuring ModSecurity base structure..."
mkdir -p /etc/nginx/modsec
mkdir -p /var/log/modsecurity/audit/

# Copy default recommended ModSecurity configuration if not present
if [ -f /etc/modsecurity/modsecurity.conf-recommended ] && [ ! -f /etc/nginx/modsec/modsecurity.conf ]; then
    cp /etc/modsecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
fi

# Copy unicode mapping table
if [ -f /etc/modsecurity/unicode.mapping ] && [ ! -f /etc/nginx/modsec/unicode.mapping ]; then
    cp /etc/modsecurity/unicode.mapping /etc/nginx/modsec/unicode.mapping
fi

# 3. Deploy Secure Portal custom configuration files
echo "[3/6] Deploying custom portal WAF configurations..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${SCRIPT_DIR}/modsec_main.conf" ]; then
    cp "${SCRIPT_DIR}/modsec_main.conf" /etc/nginx/modsec/main.conf
fi

if [ -f "${SCRIPT_DIR}/modsecurity_custom_rules.conf" ]; then
    cp "${SCRIPT_DIR}/modsecurity_custom_rules.conf" /etc/nginx/modsec/modsecurity_custom_rules.conf
fi

# Scanner user-agents data file for rule 100001
cat << 'EOF' > /etc/nginx/modsec/scanners-user-agents.data
sqlmap
nikto
nmap
masscan
zgrab
gobuster
dirbuster
ffuf
wpscan
havij
acunetix
EOF

# 4. Deploy Nginx site configuration
echo "[4/6] Deploying Nginx site configuration..."
if [ -f "${SCRIPT_DIR}/secure_portal_nginx.conf" ]; then
    cp "${SCRIPT_DIR}/secure_portal_nginx.conf" /etc/nginx/sites-available/secure_portal.conf
    ln -sf /etc/nginx/sites-available/secure_portal.conf /etc/nginx/sites-enabled/secure_portal.conf
    # Disable default Nginx welcome page
    rm -f /etc/nginx/sites-enabled/default
fi

# 5. Create default custom error pages
echo "[5/6] Creating custom HTML response pages..."
mkdir -p /usr/share/nginx/html
cat << 'EOF' > /usr/share/nginx/html/403_waf.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>403 Forbidden - WAF</title>
    <style>body{font-family:sans-serif;background:#0f172a;color:#f8fafc;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}
    .c{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:30px 40px;text-align:center;max-width:440px;}
    .b{background:#ef4444;color:#fff;font-size:12px;font-weight:bold;padding:4px 8px;border-radius:9999px;display:inline-block;margin-bottom:12px;}
    h1{margin:0 0 10px;font-size:20px;}p{color:#94a3b8;font-size:14px;line-height:1.5;margin:0;}</style>
</head>
<body><div class="c"><div class="b">WAF INTERCEPT</div><h1>403 Forbidden</h1><p>Your request was blocked by the application security firewall policy.</p></div></body>
</html>
EOF

cat << 'EOF' > /usr/share/nginx/html/429_ratelimit.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>429 Too Many Requests</title>
    <style>body{font-family:sans-serif;background:#0f172a;color:#f8fafc;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}
    .c{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:30px 40px;text-align:center;max-width:440px;}
    .b{background:#f59e0b;color:#fff;font-size:12px;font-weight:bold;padding:4px 8px;border-radius:9999px;display:inline-block;margin-bottom:12px;}
    h1{margin:0 0 10px;font-size:20px;}p{color:#94a3b8;font-size:14px;line-height:1.5;margin:0;}</style>
</head>
<body><div class="c"><div class="b">RATE LIMITED</div><h1>429 Too Many Requests</h1><p>Your request rate exceeded the server limit. Please slow down and try again.</p></div></body>
</html>
EOF

# 6. Syntax validation (non-destructive)
echo "[6/6] Validating Nginx and ModSecurity configuration syntax..."
nginx -t

echo "======================================================================"
echo "[+] SUCCESS: Nginx + ModSecurity configuration is syntactically valid."
echo ""
echo "[*] Next Steps (Manual Execution Required):"
echo "    1. Start/restart Nginx service:  sudo systemctl restart nginx"
echo "    2. Verify Flask backend binds to localhost only: FLASK_HOST=127.0.0.1 in .env"
echo "    3. Inspect live WAF logs:        sudo tail -f /var/log/modsec_audit.log"
echo "======================================================================"
