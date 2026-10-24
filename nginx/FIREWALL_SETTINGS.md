# Enterprise Firewall & WAF Configuration Reference Guide

This document consolidates all critical firewall parameters, rulesets, and defensive policies across the three perimeter defense tiers of the **Mini Enterprise Secure Portal**:

1. **Network Layer (L3/L4 OS Packet Filtering)** — `nftables` / `ufw` / `iptables` / Windows Defender Firewall
2. **Reverse-Proxy Web Application Firewall (L7 WAF)** — Nginx + ModSecurity v3 (OWASP CRS)
3. **In-Process Application Firewall & Adaptive Quarantine** — Python/Flask `WAFInspector` & `SafeDefensivePolicy`

---

## 1. Network Layer (OS Packet Filtering Firewall)

The OS packet filter is the first line of defense. Its primary objectives are:
- Allow legitimate management (SSH) and web traffic (HTTP/HTTPS).
- Drop all unsolicited inbound traffic by default.
- **Strictly drop external packets targeting Flask backend port `5000`** to prevent WAF bypass.

### A. Core Port Matrix

| Port / Protocol | Direction | Source | Destination / Interface | Action | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TCP 22** | Inbound | Admin Subnet / Any | Host External IP | **ACCEPT** | Remote SSH Administration |
| **TCP 80** | Inbound | External Clients / Any | Host External IP | **ACCEPT** | HTTP Web Traffic (Nginx Reverse Proxy) |
| **TCP 443** | Inbound | External Clients / Any | Host External IP | **ACCEPT** | HTTPS Web Traffic (TLS Termination) |
| **TCP 5000** | Inbound | `127.0.0.1` (`lo` loopback) | `127.0.0.1:5000` | **ACCEPT** | Internal Reverse Proxy to Flask Backend |
| **TCP 5000** | Inbound | External (`eth0`, `enp0s8`, `*`) | Host External IP | **DROP** | **Crucial:** Blocks direct external access to Flask |
| **All Other Ports** | Inbound | Any | Any | **DROP** | Default Inbound Policy |
| **All Ports** | Outbound | Localhost | Any | **ACCEPT** | Telemetry to SOC (`/api/events`), DNS, OS updates |

---

### B. Production `nftables` Ruleset (`/etc/nftables.conf`)

```nftables
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # 1. Accept loopback traffic (Crucial for Nginx -> Flask 127.0.0.1:5000)
        iif "lo" accept

        # 2. Accept established and related connection states
        ct state established,related accept

        # 3. Drop invalid connection packets
        ct state invalid drop

        # 4. Inbound Administrative Access (SSH)
        tcp dport 22 ct state new accept

        # 5. Inbound Web Traffic to Nginx Reverse-Proxy WAF
        tcp dport { 80, 443 } ct state new accept

        # 6. Explicitly DROP external direct access to Flask backend port 5000
        tcp dport 5000 drop

        # 7. ICMP rate-limited ping handling (mitigate ping floods)
        ip protocol icmp icmp type echo-request limit rate 5/second accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

#### Verification & Reload Commands:
```bash
sudo nft -c -f /etc/nftables.conf    # Test syntax without applying
sudo nft -f /etc/nftables.conf       # Apply ruleset
sudo nft list ruleset                # Inspect active table state
```

---

### C. Equivalent UFW (Uncomplicated Firewall) Configuration

If using Ubuntu `ufw`:
```bash
# Set baseline default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow standard management and web ingress
sudo ufw allow 22/tcp comment "SSH administration"
sudo ufw allow 80/tcp comment "Nginx HTTP"
sudo ufw allow 443/tcp comment "Nginx HTTPS"

# Explicitly deny external access to Flask port 5000
sudo ufw deny 5000/tcp comment "Block direct Flask bypass"

# Enable and inspect
sudo ufw enable
sudo ufw status verbose
```

---

### D. Windows Defender Firewall (Local Development / Testing)

```powershell
# In PowerShell (Run as Administrator):

# Allow inbound HTTP port 80 & 443
New-NetFirewallRule -DisplayName "SecurePortal-HTTP" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "SecurePortal-HTTPS" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow

# Block external inbound connections to port 5000
New-NetFirewallRule -DisplayName "Block-Direct-Flask-5000" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Block
```

---

## 2. Reverse-Proxy WAF Layer (Nginx + ModSecurity)

Configured in `nginx/secure_portal_nginx.conf` and `nginx/modsecurity_custom_rules.conf`.

### A. Nginx Rate Limiting & Proxy Constraints

| Directive | Setting | Location | Security Purpose |
| :--- | :--- | :--- | :--- |
| `limit_req_zone` | `$binary_remote_addr zone=portal_req_limit:10m rate=10r/s` | `http` block | Tracks client IP request velocity; restricts sustained rate to 10 req/s. |
| `limit_req` | `zone=portal_req_limit burst=20 nodelay` | `location /` | Permitted burst up to 20 requests without queuing delays. Returns HTTP 429 when exceeded. |
| `client_max_body_size` | `1M` | `server` block | Mitigates buffer overflow and large payload denial-of-service (DoS). |
| `client_body_buffer_size` | `128k` | `server` block | Limits memory buffering for request bodies. |
| `proxy_pass` | `http://127.0.0.1:5000` | `location /` | Internal-only proxy forwarding. |
| Hidden file block | `location ~ /\. { deny all; }` | `server` block | Prevents direct leakage of `.env`, `.git`, `.htaccess`, `.bak`. |

### B. Security Headers Configured

```nginx
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

---

### C. ModSecurity Core Settings & Inspection Engine

| Directive | Setting | Recommended Value | Security Purpose |
| :--- | :--- | :--- | :--- |
| `SecRuleEngine` | `DetectionOnly` *(Tuning)* / `On` *(Production)* | `On` | `DetectionOnly` logs alerts without blocking; `On` actively blocks attacks with HTTP 403. |
| `SecRequestBodyAccess` | `On` | `On` | Enables inspection of POST request bodies (form data, JSON payloads). |
| `SecRequestBodyLimit` | `1048576` (1 MB) | `1048576` | Rejects payloads exceeding 1MB (`SecRequestBodyLimitAction Reject`). |
| `SecResponseBodyAccess` | `Off` | `Off` | Disabled for low CPU overhead unless data leakage inspection is mandated. |
| `SecAuditEngine` | `RelevantOnly` | `RelevantOnly` | Logs entries triggering 4xx/5xx status codes to reduce disk I/O. |
| `SecAuditLog` | `/var/log/modsec_audit.log` | Default | Audit log destination parsed by detection pipelines. |

---

### D. Custom ModSecurity Rules (`modsecurity_custom_rules.conf`)

| Rule ID | Trigger Condition | Target Pattern | Action | SOC Signature |
| :--- | :--- | :--- | :--- | :--- |
| **`100001`** | Scanner User-Agents | `sqlmap`, `nikto`, `nmap`, `masscan`, `gobuster`, `dirbuster`, `ffuf`, `wpscan` | `deny, status:403` | `DIR_FUZZ` (Reconnaissance) |
| **`100002`** | Sensitive File Probes | `\.(env\|git\|svn\|htaccess\|bak\|sql\|config\|ini)$` | `deny, status:403` | `PATH_TRAVERSAL` |
| **`100003`** | Disallowed HTTP Methods | Method not in `GET`, `POST`, `HEAD` | `deny, status:405` | Protocol Violation |

---

## 3. Application-Layer In-Process WAF & Defense Policy

Configured in `security_agent/waf.py` and `security_agent/defense_policy.py`.

### A. Environment Tuning Variables (`.env`)

| Variable | Default | Threshold / Behavior |
| :--- | :--- | :--- |
| `WAF_MODE` | `BLOCK` | Set to `BLOCK` for active perimeter enforcement; `DETECT` for passive logging. |
| `WAF_AUTH_LOCKOUT_THRESHOLD` | `3` | Number of failed login attempts before initiating progressive lockout. |
| `WAF_AUTH_LOCKOUT_SECONDS` | `2` | Base lockout duration (seconds) for Tier 1 progressive lockout. |
| `WAF_AUTH_LOCKOUT_MAX_SECONDS`| `60` | Maximum cap for exponential lockout escalation (`2^(tier - 1)`). |
| `DIR_FUZZ_THRESHOLD` | `5` | Distinct 404 paths within the time window before activating IP quarantine. |
| `DIR_FUZZ_WINDOW_SECONDS` | `60` | Time window (seconds) for distinct path collection. |
| `WAF_DIR_FUZZ_THROTTLE_SECONDS`| `3` | Quarantine duration returning HTTP 429 to fuzzing IPs. |
| `PORT_SCAN_THRESHOLD` | `5` | Distinct probed destination ports within window required to trigger alert. |
| `PORT_SCAN_WINDOW_SECONDS` | `60` | Sliding window for multi-port SYN probe aggregation. |
| `PORT_SCAN_COOLDOWN_SECONDS` | `30` | Alert debouncing duration to prevent SOC notification flood. |

---

### B. Safe Policy Invariants (`SafeDefensivePolicy`)

1. **Immutable Whitelist**:
   - `127.0.0.1`, `::1`, `localhost`
   - `CN_SERVER_IP` (Server self IP)
   - `SOC_URL` host (SOC dashboard receiver)
   - *These addresses can never be blocked or quarantined under any condition.*
2. **Finite Expiration**: Every quarantine block has a mandatory TTL (`default_expiry_seconds: 300`, max 3600s) and automatically auto-expires.
3. **Emergency Rollback Commands**:
   - Administrative IP release: `detector.defense_policy.rollback_block(source_ip)`
   - Global emergency release: `detector.defense_policy.rollback_all()`

---

## 4. Verification & Testing Checklist

| Test Item | Verification Command | Expected Result |
| :--- | :--- | :--- |
| **1. Local Port 5000 External Block** | `curl -I http://<SERVER_IP>:5000/` from external machine | Connection timeout or `Connection refused` |
| **2. Nginx WAF Normal Access** | `curl -I http://<SERVER_IP>/` | `HTTP/1.1 200 OK` |
| **3. SQL Injection WAF Block** | `curl -i "http://<SERVER_IP>/?id=1'%20OR%20'1'='1"` | `HTTP/1.1 400 Bad Request` or `403 Forbidden` |
| **4. Scanner UA Detection** | `curl -i -A "sqlmap/1.5" http://<SERVER_IP>/` | `HTTP/1.1 403 Forbidden` |
| **5. Disallowed HTTP Method** | `curl -i -X PUT http://<SERVER_IP>/` | `HTTP/1.1 405 Method Not Allowed` |
| **6. Sensitive File Probe** | `curl -i http://<SERVER_IP>/.env` | `HTTP/1.1 403 Forbidden` |
| **7. Automated Unit Test Suite** | `python -m pytest tests/test_defensive_controls.py -v` | All defensive control tests pass |
