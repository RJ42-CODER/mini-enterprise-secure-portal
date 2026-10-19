# Linux CN-Server VM Hardening & WAF Architecture Guide

## 1. Production Architecture Overview

The multi-layer defensive deployment on the protected Linux CN-Server VM is structured as follows:

```
[ External Client / Attacker ]
              │
              ▼
    [ nftables Firewall ]
    (Layer 3/4 Packet Filtering: Allow Inbound TCP 80, 443, 22 only.
     Direct external traffic to TCP 5000 is DROPPED)
              │
              ▼
    [ Nginx + ModSecurity ]
    (Reverse-Proxy WAF: OWASP CRS, TLS Termination, Body Size Limits,
     Disallowed Method Filtering, HTTP Header Normalization)
              │ (Forwarding via 127.0.0.1:5000 loopback only)
              ▼
     [ Secure Portal (Flask) ]
    (Application-Layer Defense: In-process WAFInspector,
     Sliding-Window Rate Limiting, Brute-Force Lockout, Parameterized SQL)
              │
              ▼ (REST POST /api/events with Bearer Token)
     [ Defensive SOC Dashboard ]
    (Victus SOC Backend: Threat Ingestion, Signature Mapping, Incident Timeline)
```

---

## 2. Preventing Direct Access to the Flask Backend (WAF Bypass Mitigation)

In production, external clients must **never** be permitted to bypass Nginx/ModSecurity by communicating directly with Flask on port 5000.

### A. Application Binding
In `/etc/secure-portal/.env` on the Linux CN-Server:
```env
FLASK_HOST=127.0.0.1
PORT=5000
```
This restricts Python's socket binding to the local loopback interface (`lo`). External network interfaces (`enp0s3`, `enp0s8`, `eth0`) will reject connection attempts at the OS TCP stack level.

### B. Network Firewall (`nftables`) Verification
Verify that your existing `nftables` ruleset restricts port 5000 to the loopback interface.

**Inspection:**
```bash
sudo nft list ruleset
```

**Target Policy (Reference only — do not overwrite existing tables):**
```nftables
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Accept loopback traffic (allows Nginx -> Flask 127.0.0.1:5000)
        iif "lo" accept

        # Accept established and related traffic
        ct state established,related accept

        # Inbound SSH administration
        tcp dport 22 accept

        # Inbound HTTP/HTTPS to Nginx Reverse-Proxy WAF
        tcp dport { 80, 443 } accept

        # Explicitly drop any external packet targeting backend port 5000
        tcp dport 5000 drop
    }
}
```

---

## 3. False-Positive Review and Tuning Workflow

ModSecurity with the OWASP Core Rule Set (CRS) provides comprehensive protection against OWASP Top 10 web vulnerabilities. To avoid disrupting legitimate enterprise users:

### Step 1: Initial Baseline in Detection-Only Mode
Set `SecRuleEngine DetectionOnly` in `/etc/nginx/modsec/modsecurity_custom_rules.conf`:
```apache
SecRuleEngine DetectionOnly
```
Reload Nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

### Step 2: Analyze Audit Logs for False Positives
Monitor the audit log during standard user activities (login, password reset, complex form submissions):
```bash
sudo tail -f /var/log/modsec_audit.log | grep -E "ModSecurity: (Warning|Access denied)"
```

Extract triggering Rule IDs (e.g. `942100` for SQLi anomaly or `941100` for XSS anomaly).

### Step 3: Implement Targeted Rule Exclusions
Do not disable the entire WAF. Add specific rule exclusions in `/etc/nginx/modsec/modsecurity_custom_rules.conf`:
```apache
# Example: Exclude password field from SQL injection inspection on login form
SecRuleUpdateTargetById 942100 "!ARGS:password"
SecRuleUpdateTargetById 941100 "!ARGS:password"
```

### Step 4: Enable Active Blocking
Once zero false positives are observed for at least 48 hours of normal use:
```apache
SecRuleEngine On
```
Reload Nginx to enforce active rejection.

---

## 4. SOC Dashboard Event Mapping Reference

| Attack Category | ModSecurity CRS Rule Set | Secure Portal In-Process WAF | SOC Ingestion Signature | MITRE ATT&CK Mapping |
| :--- | :--- | :--- | :--- | :--- |
| **SQL Injection** | CRS 942xxx (SQLi Rules) | `WAFInspector.SQLI_PATTERNS` | `SQL_INJECTION` | T1190 (Exploit Public-Facing App) |
| **Cross-Site Scripting** | CRS 941xxx (XSS Rules) | `WAFInspector.XSS_PATTERNS` | `COMMAND_INJECTION` | T1059 (Command/Script Interpreter) |
| **Path Traversal** | CRS 930xxx (LFI / Traversal) | `WAFInspector.TRAVERSAL_PATTERNS`| `PATH_TRAVERSAL` | T1083 (File/Directory Discovery) |
| **Command Injection** | CRS 932xxx (RCE Rules) | `WAFInspector.CMDI_PATTERNS` | `COMMAND_INJECTION` | T1059 (Command Execution) |
| **Reconnaissance Fuzzing** | CRS 913xxx (Scanner UA) | `WAFInspector.SCANNER_AGENTS` | `DIR_FUZZ` | T1595 (Active Scanning) |
| **Disallowed HTTP Method**| Nginx `REQUEST_METHOD` | `WAFInspector.config.allowed_methods`| `DIR_FUZZ` | T1595 (Active Scanning) |
| **Oversized Request Body**| Nginx `client_max_body_size` | Flask `MAX_CONTENT_LENGTH` | `DIR_FUZZ` | T1499 (Endpoint DoS) |
| **Rate Limit Exceeded** | Nginx `limit_req_zone` | `RateLimiter` (120 req/min) | `DIR_FUZZ` | T1499 (Endpoint DoS) |
| **Brute-Force Lockout** | Fail2ban / IP Tables | `BruteForceProtector` (3 fails) | `BRUTE_FORCE_AUTH` | T1110 (Brute Force) |
