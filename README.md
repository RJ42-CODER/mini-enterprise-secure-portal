# Secure Portal & Edge Security Agent

This repository contains the **Protected Enterprise Web Server** and its integrated **Security Monitoring Agent** for the college cybersecurity project: *Mini Enterprise: Secure Portal + Defensive SOC Dashboard*.

---

## 1. Architecture Overview

The system consists of two primary operational components:

1. **Secure Portal Web Application (`app.py`):**
   - Lightweight Flask application listening on port `5000` (configurable via `PORT`).
   - Presents the enterprise portal authentication interface.
   - Synchronously inspects incoming HTTP requests (`@app.before_request`) across URL paths, query parameters, HTTP headers, and submitted form bodies for attack signatures.
   - Tracks failed authentication attempts with a 5-minute sliding window decay policy to identify brute-force bursts.
   - Logs successful authentications (`LOGIN_SUCCESS`) and clears previous failure history.

2. **Security Monitoring Agent (`security_agent/`):**
   - **`detector.py` (`ServerDetector`):** Core detection rule engine. Maps raw attacks to registered SOC signatures (`SQL_INJECTION`, `COMMAND_INJECTION`, `PATH_TRAVERSAL`, `DIR_FUZZ`, `BRUTE_FORCE_AUTH`, `PORT_SCAN`).
   - **`alert_client.py` (`AlertClient`):** Transmits structured telemetry to the SOC Ingestion API (`POST {SOC_URL}/api/events`) using Bearer token authentication. Implements resilient local disk buffering (`logs/event_spool.jsonl`) for transient network partitions and 5xx server errors, safely accepting HTTP `200`, `201`, and `202 Accepted`.
   - **`event_logger.py` (`EventLogger`):** Appends structured JSON records to local disk audit logs (`logs/security.log`) with timezone-aware ISO UTC timestamps.
   - **`network_sniffer.py` (`NetworkSniffer`):** Standalone multi-threaded daemon featuring a thread-safe sliding-window `PortScanTracker`. Captures raw TCP SYN probes via `tcpdump` or `tshark` on the configured interface (e.g. `enp0s8`) and canary socket listeners on sentinel ports (`21, 22, 80, 443, 5050, 8080`). Aggregates distinct probed destination ports within a sliding time window, suppresses repetitive packet bursts, applies cooldown debouncing, and transmits a consolidated `PORT_SCAN` event (MITRE ATT&CK T1046: Network Service Discovery) to the SOC ingestion backend. Prevents duplicate daemon execution using an OS-level file lock (`logs/network_sniffer.pid`).

---

## 2. Environment Configuration

Copy the template to `.env`:

```bash
cp .env.example .env
```

Configure the following variables in `.env`:

| Variable | Description | Required | Example Default |
|---|---|---|---|
| `CN_SERVER_IP` | IP address of this protected server VM | **Yes** | `192.168.31.91` |
| `SOC_URL` | Base URL of the Defensive SOC Dashboard | **Yes** | `http://192.168.31.204:5050` |
| `SOC_API_KEY` | Telemetry Bearer token (*or* `SOC_AGENT_TOKEN`) | **Yes** | (Set secret token) |
| `PORT` | Local web server listening port | No | `5000` |
| `PORTAL_ADMIN_PASSWORD` | Portal admin password | No | `admin123` |
| `SOC_EVENTS_ENDPOINT` | Custom endpoint override | No | `${SOC_URL}/api/events` |
| `SNIFFER_INTERFACE` | Network interface for `tcpdump`/`tshark` | No | `enp0s8` (Linux) / `any` |
| `SNIFFER_ALLOW_LOCALHOST` | Process loopback probes (`127.0.0.1`) | No | `True` |
| `MONITORED_PORTS` | Comma-separated canary ports | No | `21,22,80,443,5050,8080` |
| `PORT_SCAN_THRESHOLD` | Distinct destination ports required to trigger scan alert | No | `5` |
| `PORT_SCAN_WINDOW_SECONDS` | Sliding time window (in seconds) for distinct port aggregation | No | `60` |
| `PORT_SCAN_COOLDOWN_SECONDS` | Cooldown period (in seconds) suppressing duplicate alerts | No | `30` |
| `PORT_SCAN_SEVERITY` | Severity assigned to confirmed port scan alerts | No | `HIGH` |

*Note: Environment variables are automatically loaded from `.env` via `python-dotenv` if present.*

---

## 3. Installation & Startup Instructions

### Prerequisites
- Python 3.10+
- Linux VM (Ubuntu/Debian) or local development workstation
- `tcpdump` or `tshark` installed (`sudo apt-get install -y tcpdump`)

### Setup
```bash
# 1. Create a clean virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt
```

### Running the Services

The web server and network sniffer are intentionally decoupled to separate unprivileged web traffic from privileged network packet capture:

#### Option A: Production Daemon via Systemd (Recommended)
Install the provided systemd service unit to manage the sniffer independently with automatic restarts and single-instance PID enforcement:
```bash
sudo cp systemd/secure-portal-sniffer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now secure-portal-sniffer.service
sudo systemctl status secure-portal-sniffer.service
```

#### Option B: Foreground Standalone Execution (Development & Testing)
**Terminal 1 — Start Web Portal:**
```bash
python app.py
```
*Listens on `http://0.0.0.0:5000`.*

**Terminal 2 — Start Network Sniffer:**
```bash
# On Linux, raw packet capture requires root or CAP_NET_RAW / CAP_NET_BIND_SERVICE
sudo python -m security_agent.network_sniffer
```
*Monitors interface `enp0s8` with PID locking (`logs/network_sniffer.pid`) to guarantee a single active sensor.*

---

## 4. SOC Ingestion Telemetry Contract

Outgoing alerts sent to `POST {SOC_URL}/api/events` conform to the following JSON schema:

```json
{
  "event_id": "EVT-HP-XXXXXXXX",
  "timestamp": "2026-10-18 12:00:00Z",
  "source": "hp-server",
  "event_type": "SQL_INJECTION",
  "signature": "SQL_INJECTION",
  "alert_type": "SQL_INJECTION",
  "severity": "CRITICAL",
  "source_ip": "192.168.31.200",
  "destination_ip": "192.168.31.91",
  "source_port": null,
  "destination_port": 5000,
  "protocol": "TCP",
  "message": "SQL injection attempt pattern '' or '1'='1' detected in request",
  "metadata": {
    "query": "/?id=' or '1'='1",
    "body": ""
  },
  "is_test": 0
}
```

### Supported Registered Signatures
- `SQL_INJECTION` (Severity: `CRITICAL`)
- `COMMAND_INJECTION` (Severity: `CRITICAL`)
- `PATH_TRAVERSAL` (Severity: `HIGH`)
- `DIR_FUZZ` (Severity: `HIGH`)
- `BRUTE_FORCE_AUTH` (Severity: `LOW` on initial failure, `HIGH` on ≥3 attempts within 5 minutes)
- `PORT_SCAN` (Severity: `HIGH` for aggregated scan detections, `LOW` for individual probe records; mapped to MITRE ATT&CK T1046)

---

## 5. Attack-Specific Defensive Controls & Mitigation Architecture

The Secure Portal enforces stateful, attack-specific defensive controls directly on the server and records empirical verification evidence:

### 1. Progressive Brute-Force Lockout
- **Mechanism**: Exponential escalation on repeated authentication failures (`lockout_seconds * 2^(tier - 1)` up to `max_lockout_seconds`).
- **Perimeter Enforcement**: Intercepts subsequent authentication requests at the WAF layer, returning `HTTP 429 Too Many Requests` with a dynamic `Retry-After: <seconds>` header.
- **Rollback / Reset**: Legitimate successful authentication immediately clears failure counters and progressive lockout tiers.

### 2. Directory-Fuzzing Throttling
- **Mechanism**: Sliding-window tracking of distinct `HTTP 404 Not Found` paths per source IP. Reaching threshold (default: 5 distinct paths in 60s) or reconnaissance User-Agents (`gobuster`, `ffuf`, `dirbuster`, `nikto`) triggers active quarantine.
- **Perimeter Enforcement**: Quarantined client IPs are rejected on all subsequent requests across the application with `HTTP 429 Too Many Requests` and `Retry-After`.

### 3. Application Firewall (WAF) Rejection
- **Mechanism**: Rejection of SQL Injection, OS Command Injection, Directory Traversal, Cross-Site Scripting (XSS), Disallowed HTTP methods, and Oversized request bodies.
- **Perimeter Enforcement**: Malicious requests are rejected prior to reaching backend business logic with appropriate status codes (`HTTP 400`, `403`, `405`, `413`).

### 4. Aggregated PORT_SCAN Detection
- **Mechanism**: Thread-safe sliding-window tracking of inbound TCP SYN probes across distinct destination ports, suppressing packet floods.
- **Mitigation Action**: Emits a single aggregated detection mapped to MITRE ATT&CK T1046 (Network Service Discovery) with cooldown deduplication and empirical probe sample evidence.

### 5. Safe Defensive Policy & Rollback
- **Whitelist Invariants**: Loopback (`127.0.0.1`, `::1`), `CN_SERVER_IP`, and the SOC server hostname are strictly whitelisted and immune to blocking.
- **Finite Expiry**: All active quarantines have immutable expiration limits and auto-expire cleanly.
- **Rollback Mechanics**: Administrative release per IP via `detector.reset_ip_defenses(source_ip)` or emergency global perimeter rollback via `policy.rollback_all()`.

---

## 6. Structured Mitigation Evidence Ledger (`logs/mitigations.log`)

Every defensive control records an immutable structured mitigation record to `logs/mitigations.log` and the in-memory ledger with the following schema:

```json
{
  "action_id": "ACT-MIT-XXXXXXXX",
  "event_id": "EVT-HP-XXXXXXXX",
  "attack_type": "SQL_INJECTION",
  "source": "192.168.31.200",
  "target": "192.168.31.91:5000",
  "action_taken": "BLOCKED",
  "timestamp": "2026-10-21T18:30:00.000000+00:00",
  "outcome": "BLOCKED",
  "verification_evidence": {
    "status_code": 400,
    "rule": "SQLI_PATTERN_DETECTED",
    "pattern": "union(\\s+all)?\\s+select",
    "perimeter_enforced": true,
    "verification_status": "VERIFIED"
  }
}
```

---

## 7. Running Automated Unit Tests

Run the full pytest suite:

```bash
python -m pytest tests/ -v
```
