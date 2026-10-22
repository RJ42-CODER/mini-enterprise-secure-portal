import os
import sys
import time
import socket
import select
import shutil
import threading
import subprocess  # nosec B404
from pathlib import Path
from typing import Optional, List, Set, Dict, Any, Tuple, Union

# Ensure hp-server modules can be imported
AGENT_DIR = Path(__file__).resolve().parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

try:
    from .config import load_portal_env, validate_portal_config
    load_portal_env()
    from .detector import ServerDetector
except ImportError:
    try:
        from config import load_portal_env, validate_portal_config
        load_portal_env()
    except ImportError:
        pass
    from detector import ServerDetector


class ProbeRecord:
    """Represents a single inbound port probe record."""
    __slots__ = ("timestamp", "port", "flag", "packet_time", "target_ip")

    def __init__(
        self,
        timestamp: float,
        port: int,
        flag: Optional[str] = None,
        packet_time: Optional[str] = None,
        target_ip: Optional[str] = None
    ):
        self.timestamp = timestamp
        self.port = port
        self.flag = flag
        self.packet_time = packet_time
        self.target_ip = target_ip


class PortScanTracker:
    """
    Thread-safe, bounded sliding-window tracker for distinct destination ports.
    Aggregates inbound probes per source IP.
    When distinct ports probed within window_seconds >= threshold, triggers an alert
    if cooldown_seconds has elapsed since the last alert for this source IP.
    """

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: float = 60.0,
        cooldown_seconds: float = 30.0,
        max_tracked_ips: int = 1000,
        severity: str = "HIGH"
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.max_tracked_ips = max_tracked_ips
        self.severity = severity

        # source_ip -> list of ProbeRecord
        self.probes: Dict[str, List[ProbeRecord]] = {}
        # source_ip -> float (timestamp of last alert)
        self.last_alert_time: Dict[str, float] = {}
        # source_ip -> float (timestamp of last seen probe, for LRU pruning)
        self.last_seen: Dict[str, float] = {}
        self._lock = threading.Lock()

    def record_probe(
        self,
        source_ip: str,
        destination_port: int,
        target_ip: Optional[str] = None,
        flag: Optional[str] = None,
        packet_time: Optional[str] = None,
        current_time: Optional[float] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Record an inbound probe from source_ip to destination_port.
        Returns:
            (True, alert_info_dict) if distinct ports in the sliding window >= threshold
            AND cooldown_seconds has elapsed since the last alert for this source_ip.
            (False, None) otherwise.
        """
        now = current_time if current_time is not None else time.time()
        with self._lock:
            self.last_seen[source_ip] = now
            history = self.probes.get(source_ip, [])
            window_start = now - self.window_seconds

            # Prune probes outside the sliding time window for this IP
            active = [p for p in history if p.timestamp > window_start]
            active.append(ProbeRecord(
                timestamp=now,
                port=destination_port,
                flag=flag,
                packet_time=packet_time,
                target_ip=target_ip
            ))

            # Keep per-IP history bounded to prevent unbounded memory growth
            if len(active) > 500:
                active = active[-500:]
            self.probes[source_ip] = active

            # Periodically prune stale tracking entries if capacity is reached
            if len(self.probes) > self.max_tracked_ips:
                self._prune_stale(now)

            # Extract distinct destination ports probed in this sliding window
            distinct_ports = sorted(list(set(p.port for p in active)))
            distinct_count = len(distinct_ports)

            if distinct_count >= self.threshold:
                last_alert = self.last_alert_time.get(source_ip, 0.0)
                if now - last_alert < self.cooldown_seconds:
                    # Cooldown active: suppress duplicate alert to prevent SOC event flooding
                    return False, None

                # Threshold reached and cooldown passed -> trigger aggregated alert!
                self.last_alert_time[source_ip] = now

                target = target_ip or next((p.target_ip for p in reversed(active) if p.target_ip), None)
                flags_seen = sorted(list(set(p.flag for p in active if p.flag)))
                pkt_times = [p.packet_time for p in active if p.packet_time][-5:]
                first_ts = active[0].timestamp
                last_ts = active[-1].timestamp
                duration = round(last_ts - first_ts, 2)

                msg = (
                    f"TCP port scan detected from {source_ip}"
                    f"{f' targeting {target}' if target else ''}: "
                    f"{distinct_count} distinct ports probed within {self.window_seconds}s window"
                )

                info = {
                    "source_ip": source_ip,
                    "target_ip": target,
                    "distinct_ports_count": distinct_count,
                    "observed_ports": distinct_ports,
                    "detection_window": self.window_seconds,
                    "duration_seconds": duration,
                    "first_probe_time": first_ts,
                    "last_probe_time": last_ts,
                    "tcp_flags": flags_seen or ["SYN"],
                    "packet_timestamps": pkt_times,
                    "severity": self.severity,
                    "message": msg
                }
                return True, info

            return False, None

    def _prune_stale(self, now: float):
        """Remove IPs that have no probes within window_seconds or evict oldest by last_seen."""
        window_start = now - self.window_seconds
        stale_ips = []
        for ip, probe_list in self.probes.items():
            if not probe_list or probe_list[-1].timestamp <= window_start:
                stale_ips.append(ip)

        for ip in stale_ips:
            self.probes.pop(ip, None)
            self.last_seen.pop(ip, None)
            self.last_alert_time.pop(ip, None)

        if len(self.probes) > self.max_tracked_ips:
            sorted_by_seen = sorted(self.last_seen.items(), key=lambda x: x[1])
            excess = len(self.probes) - self.max_tracked_ips
            for ip, _ in sorted_by_seen[:excess]:
                self.probes.pop(ip, None)
                self.last_seen.pop(ip, None)
                self.last_alert_time.pop(ip, None)

    def reset_ip(self, source_ip: str):
        """Reset tracking state for a specific source IP."""
        with self._lock:
            self.probes.pop(source_ip, None)
            self.last_alert_time.pop(source_ip, None)
            self.last_seen.pop(source_ip, None)

    def clear(self):
        """Clear all tracked IP probe histories and alert timestamps."""
        with self._lock:
            self.probes.clear()
            self.last_alert_time.clear()
            self.last_seen.clear()

    def get_tracked_ip_count(self) -> int:
        """Return count of actively tracked source IPs."""
        with self._lock:
            return len(self.probes)


class SingleInstanceLock:
    """Ensures only one instance of the sniffer runs at any given time via OS-level file lock."""

    def __init__(self, lock_file: Path):
        self.lock_file = lock_file
        self.lock_fd = None

    def acquire(self) -> bool:
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.lock_fd = open(self.lock_file, "a+", encoding="utf-8")
            self.lock_fd.seek(0)
            if sys.platform != "win32":
                import fcntl
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt
                msvcrt.locking(self.lock_fd.fileno(), msvcrt.LK_NBLCK, 1)

            self.lock_fd.seek(0)
            self.lock_fd.truncate()
            self.lock_fd.write(f"{os.getpid()}\n")
            self.lock_fd.flush()
            return True
        except (IOError, OSError):
            if self.lock_fd:
                try:
                    self.lock_fd.close()
                except Exception:
                    pass
                self.lock_fd = None
            return False

    def release(self):
        if self.lock_fd:
            try:
                if sys.platform != "win32":
                    import fcntl
                    fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
                else:
                    import msvcrt
                    self.lock_fd.seek(0)
                    msvcrt.locking(self.lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
                self.lock_fd.close()
            except Exception:
                pass
            self.lock_fd = None
            try:
                if self.lock_file.exists():
                    self.lock_file.unlink()
            except Exception:
                pass


class NetworkSniffer:
    """
    Network Telemetry Monitor on Protected Enterprise Server.
    Captures raw TCP SYN / connection probes targeting protected asset ports
    and feeds structured, aggregated PORT_SCAN telemetry into the Security Agent detector.

    Supported capture engines:
    1. System tshark / tcpdump SYN packet monitor (preferred when available).
    2. Multi-port socket sentinel / canary listener for unserved ports.
    """

    DEFAULT_PROBE_PORTS = [21, 22, 80, 443, 5050, 8080]

    def __init__(
        self,
        detector: Optional[ServerDetector] = None,
        soc_url: Optional[str] = None,
        api_key: Optional[str] = None,
        monitored_ports: Optional[List[int]] = None,
        interface: Optional[str] = None,
        allow_localhost: Optional[bool] = None,
        scan_threshold: Optional[int] = None,
        scan_window: Optional[float] = None,
        scan_cooldown: Optional[float] = None,
        scan_severity: Optional[str] = None,
        pid_file: Optional[Union[str, Path]] = None
    ):
        self.detector = detector or ServerDetector(soc_url=soc_url, api_key=api_key)

        # Default interface: 'lo0' on macOS if localhost, otherwise 'any'
        default_iface = "lo0" if sys.platform == "darwin" else "any"
        self.interface = interface or os.getenv("SNIFFER_INTERFACE", default_iface)

        if allow_localhost is None:
            self.allow_localhost = os.getenv("SNIFFER_ALLOW_LOCALHOST", "True").lower() in ("true", "1", "yes")
        else:
            self.allow_localhost = allow_localhost

        self.monitored_ports = monitored_ports or self._get_configured_ports()

        # Sliding-window port-scan tracker configuration
        self.scan_threshold = scan_threshold if scan_threshold is not None else int(os.getenv("PORT_SCAN_THRESHOLD", "5"))
        self.scan_window = scan_window if scan_window is not None else float(os.getenv("PORT_SCAN_WINDOW_SECONDS", "60"))
        self.scan_cooldown = scan_cooldown if scan_cooldown is not None else float(os.getenv("PORT_SCAN_COOLDOWN_SECONDS", "30"))
        self.scan_severity = scan_severity or os.getenv("PORT_SCAN_SEVERITY", "HIGH")

        self.tracker = PortScanTracker(
            threshold=self.scan_threshold,
            window_seconds=self.scan_window,
            cooldown_seconds=self.scan_cooldown,
            severity=self.scan_severity
        )

        base_dir = Path(__file__).resolve().parent.parent
        self.pid_file = Path(pid_file) if pid_file else (base_dir / "logs" / "network_sniffer.pid")
        self.single_instance_lock = SingleInstanceLock(self.pid_file)

        self.running = False
        self._threads: List[threading.Thread] = []
        self._sockets: List[socket.socket] = []
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()

    def _get_configured_ports(self) -> List[int]:
        env_ports = os.getenv("MONITORED_PORTS")
        if env_ports:
            try:
                return [int(p.strip()) for p in env_ports.split(",") if p.strip()]
            except ValueError:
                pass
        return list(self.DEFAULT_PROBE_PORTS)

    def handle_probe(
        self,
        source_ip: str,
        destination_port: int,
        protocol: str = "TCP",
        is_test: int = 0,
        flags: Optional[str] = None,
        timestamp: Optional[str] = None,
        destination_ip: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Process detected inbound probe and forward to sliding-window tracker."""
        if not source_ip:
            return None

        is_loopback = source_ip in ("127.0.0.1", "::1")
        if is_loopback and not self.allow_localhost:
            return None

        configured_target_ip = os.getenv("CN_SERVER_IP")
        if configured_target_ip and destination_ip and destination_ip != configured_target_ip:
            return None
        target_ip = destination_ip or configured_target_ip

        detected, alert_info = self.tracker.record_probe(
            source_ip=source_ip,
            destination_port=destination_port,
            target_ip=target_ip,
            flag=flags or "SYN",
            packet_time=timestamp
        )

        if detected and alert_info:
            print(f"[!] [SNIFFER] {alert_info['message']}")
            if hasattr(self.detector, "record_port_scan"):
                return self.detector.record_port_scan(
                    source_ip=source_ip,
                    distinct_ports=alert_info["observed_ports"],
                    target_ip=alert_info.get("target_ip") or target_ip,
                    window_seconds=alert_info.get("detection_window"),
                    duration_seconds=alert_info.get("duration_seconds"),
                    message=alert_info.get("message"),
                    metadata={
                        "tcp_flags": alert_info.get("tcp_flags", ["SYN"]),
                        "packet_timestamps": alert_info.get("packet_timestamps", [])
                    },
                    severity=alert_info.get("severity", "HIGH"),
                    is_test=is_test
                )
            else:
                return self.detector.record_network_connection(
                    source_ip=source_ip,
                    destination_port=destination_port,
                    protocol=protocol,
                    message=alert_info.get("message"),
                    is_test=is_test
                )
        return None

    def start_canary_listeners(self, bind_ip: str = "0.0.0.0"):  # nosec B104
        """
        Start non-blocking canary listeners on specified sentinel ports.
        Instantly detects connection attempts on ports without legitimate services.
        """
        for port in self.monitored_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((bind_ip, port))
                s.listen(5)
                s.setblocking(False)
                self._sockets.append(s)

                t = threading.Thread(
                    target=self._canary_worker,
                    args=(s, port),
                    name=f"canary-port-{port}",
                    daemon=True
                )
                t.start()
                self._threads.append(t)
                print(f"[*] [SNIFFER] Canary listener active on port {port}/TCP")
            except (PermissionError, OSError) as e:
                # Port might already be in use or requires root/admin privilege
                print(f"[-] [SNIFFER] Cannot bind canary to port {port}: {e}")

    def _canary_worker(self, sock: socket.socket, port: int):
        while self.running:
            try:
                rlist, _, _ = select.select([sock], [], [], 0.5)
                if not rlist:
                    continue
                client_sock, client_addr = sock.accept()
                src_ip = client_addr[0]
                self.handle_probe(
                    source_ip=src_ip,
                    destination_port=port,
                    protocol="TCP",
                    destination_ip=os.getenv("CN_SERVER_IP")
                )
                client_sock.close()
            except Exception:
                if not self.running:
                    break
                time.sleep(0.1)

    def start_pcap_engine(self) -> bool:
        """
        Launch system tcpdump or tshark to inspect inbound TCP SYN packets.
        Returns True if process started, False otherwise.
        """
        cmd = None
        tshark_path = shutil.which("tshark")
        tcpdump_path = shutil.which("tcpdump")

        if tshark_path:
            cmd = [
                tshark_path,
                "-i", self.interface,
                "-n", "-l",
                "-Y", "tcp.flags.syn == 1 and tcp.flags.ack == 0",
                "-T", "fields",
                "-e", "frame.time",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "tcp.dstport",
                "-e", "tcp.flags"
            ]
        elif tcpdump_path:
            cmd = [
                tcpdump_path,
                "-l", "-nn", "-q",
                "-i", self.interface,
                "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0"
            ]

        if not cmd:
            return False

        try:
            self._proc = subprocess.Popen(  # nosec B603
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            t = threading.Thread(target=self._pcap_worker, daemon=True, name="pcap-parser")
            t.start()
            self._threads.append(t)
            print(f"[*] [SNIFFER] Packet capture daemon running via {cmd[0]} on interface {self.interface}")
            return True
        except Exception as e:
            print(f"[-] [SNIFFER] Failed to start packet capture engine: {e}")
            return False

    def _pcap_worker(self):
        """Parse tshark/tcpdump stdout stream into structured telemetry."""
        if not self._proc or not self._proc.stdout:
            return

        import re
        tcpdump_regex = re.compile(
            r"^(?:(?P<timestamp>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+)?.*?"
            r"IP\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\.(?P<src_port>\d+)\s*>\s*"
            r"(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\.(?P<dst_port>\d+):\s*"
            r"Flags\s*\[(?P<flags>.*?)\]"
        )

        for line in self._proc.stdout:
            if not self.running:
                break
            line_str = line.strip()
            if not line_str:
                continue

            # TShark format: tab-separated
            if "\t" in line_str:
                parts = line_str.split("\t")
                if len(parts) >= 4:
                    try:
                        pkt_time = parts[0].strip()
                        src_ip = parts[1].strip()
                        dst_ip = parts[2].strip()
                        dst_port = int(parts[3].strip())
                        flags = parts[4].strip() if len(parts) > 4 else "SYN"

                        target_ip = os.getenv("CN_SERVER_IP")
                        if target_ip and dst_ip and dst_ip != target_ip:
                            continue

                        self.handle_probe(
                            source_ip=src_ip,
                            destination_port=dst_port,
                            protocol="TCP",
                            flags=flags,
                            timestamp=pkt_time,
                            destination_ip=dst_ip
                        )
                    except (ValueError, IndexError):
                        continue
                elif len(parts) >= 2:
                    try:
                        src_ip = parts[0].strip()
                        dst_port = int(parts[1].strip())
                        self.handle_probe(
                            source_ip=src_ip,
                            destination_port=dst_port,
                            protocol="TCP",
                            flags="SYN"
                        )
                    except ValueError:
                        continue
            # Tcpdump format
            else:
                match = tcpdump_regex.search(line_str)
                if match:
                    src_ip = match.group("src_ip")
                    dst_ip = match.group("dst_ip")
                    dst_port = int(match.group("dst_port"))
                    flags = match.group("flags")
                    pkt_time = match.group("timestamp")

                    target_ip = os.getenv("CN_SERVER_IP")
                    if target_ip and dst_ip != target_ip:
                        continue

                    # Filter for SYN packets without ACK
                    if "S" in flags and "." not in flags:
                        self.handle_probe(
                            source_ip=src_ip,
                            destination_port=dst_port,
                            protocol="TCP",
                            flags=flags,
                            timestamp=pkt_time,
                            destination_ip=dst_ip
                        )

    def start(self, enforce_single_instance: bool = False) -> bool:
        """Start sniffer engine (pcap + canary listeners)."""
        if enforce_single_instance:
            if not self.single_instance_lock.acquire():
                print(f"[-] [SNIFFER] Another instance of NetworkSniffer is already active ({self.pid_file}). Exiting.")
                return False

        self.running = True
        self.start_pcap_engine()
        self.start_canary_listeners()
        print(f"[*] [SNIFFER] Network telemetry monitoring operational on {self.interface} "
              f"(Threshold: {self.scan_threshold} distinct ports in {self.scan_window}s, "
              f"Cooldown: {self.scan_cooldown}s).")
        return True

    def stop(self):
        """Stop all sniffer threads and listeners, and release single instance lock."""
        self.running = False
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception as e:
                print(f"[-] [SNIFFER] Warning terminating pcap proc: {e}")
            self._proc = None
        for s in self._sockets:
            try:
                s.close()
            except Exception as e:
                print(f"[-] [SNIFFER] Warning closing socket: {e}")
        self._sockets.clear()

        self.single_instance_lock.release()
        print("[*] [SNIFFER] Stopped network telemetry monitoring.")


if __name__ == "__main__":
    load_portal_env()
    config = validate_portal_config()
    cn_server_ip = config["CN_SERVER_IP"]
    soc_url = config["SOC_URL"]
    api_key = os.getenv("SOC_API_KEY") or os.getenv("SOC_AGENT_TOKEN")

    print("[CONFIG] Network Sniffer initializing with validated parameters:")
    print(f"  CN_SERVER_IP = {cn_server_ip}")
    print(f"  SOC_URL      = {soc_url}")
    print(f"  INTERFACE    = {os.getenv('SNIFFER_INTERFACE', 'enp0s8')}")
    print(f"  THRESHOLD    = {os.getenv('PORT_SCAN_THRESHOLD', '5')} distinct ports in {os.getenv('PORT_SCAN_WINDOW_SECONDS', '60')}s")
    print(f"  COOLDOWN     = {os.getenv('PORT_SCAN_COOLDOWN_SECONDS', '30')}s")
    print(f"  SEVERITY     = {os.getenv('PORT_SCAN_SEVERITY', 'HIGH')}")
    print("  SOC AUTH     = [CONFIGURED]")

    sniffer = NetworkSniffer(soc_url=soc_url, api_key=api_key)
    if not sniffer.start(enforce_single_instance=True):
        sys.exit(1)

    import signal

    def handle_exit_signal(sig, frame):
        print(f"\n[*] Caught signal {sig}, terminating sniffer...")
        sniffer.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit_signal)
    if sys.platform != "win32":
        signal.signal(signal.SIGTERM, handle_exit_signal)

    try:
        while sniffer.running:
            time.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()
