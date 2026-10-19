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
   - **`network_sniffer.py` (`NetworkSniffer`):** Standalone multi-threaded daemon. Binds canary socket listeners to unserved sentinel ports (`21, 22, 80, 443, 5050, 8080`) and captures raw TCP SYN probes via `tcpdump` or `tshark` on the specified network interface (e.g. `enp0s8`).

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

*Note: Environment variables are automatically loaded from `.env` via `python-dotenv` if present.*

---

## 3. Installation & Startup Instructions

### Prerequisites
- Python 3.10+
- Linux VM (Ubuntu/Debian) or local development workstation

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

#### Terminal 1 — Start Web Portal:
```bash
python app.py
```
*Listens on `http://0.0.0.0:5000`.*

#### Terminal 2 — Start Network Sniffer (Optional for Port Scan Telemetry):
```bash
# On Linux, binding to ports < 1024 (21, 22, 80, 443) requires root or CAP_NET_BIND_SERVICE
sudo python -m security_agent.network_sniffer
```

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
- `PORT_SCAN` (Severity: `INFO`)

---

## 5. Running Automated Unit Tests

Run the full pytest suite:

```bash
python -m pytest tests/ -v
```
