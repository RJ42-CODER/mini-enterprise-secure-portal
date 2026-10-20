import os
import sys
import time
import socket
import select
import shutil
import threading
import subprocess  # nosec B404
from pathlib import Path
from typing import Optional, List, Set

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

class NetworkSniffer:
    """
    Network Telemetry Monitor on HP Victus server.
    Captures raw TCP SYN / connection probes targeting protected asset ports
    and feeds structured PORT_SCAN telemetry into the Security Agent detector.
    
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
        allow_localhost: Optional[bool] = None
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
        self.running = False
        self._threads: List[threading.Thread] = []
        self._sockets: List[socket.socket] = []
        self._proc: Optional[subprocess.Popen] = None
        self._recent_probes: Set[str] = set()
        self._lock = threading.Lock()

    def _get_configured_ports(self) -> List[int]:
        env_ports = os.getenv("MONITORED_PORTS")
        if env_ports:
            try:
                return [int(p.strip()) for p in env_ports.split(",") if p.strip()]
            except ValueError:
                pass
        return list(self.DEFAULT_PROBE_PORTS)

    def handle_probe(self, source_ip: str, destination_port: int, protocol: str = "TCP", is_test: int = 0):
        """Process detected inbound probe and forward to detector."""
        if not source_ip:
            return

        is_loopback = source_ip in ("127.0.0.1", "::1")
        if is_loopback and not self.allow_localhost:
            return

        # Deduplicate high-frequency packet bursts from same (ip, port) within 1 second
        key = f"{source_ip}:{destination_port}:{int(time.time())}"
        with self._lock:
            if key in self._recent_probes:
                return
            self._recent_probes.add(key)
            # Prune old cache keys periodically
            if len(self._recent_probes) > 1000:
                self._recent_probes.clear()

        print(f"[*] [SNIFFER] Network connection probe detected from {source_ip} -> port {destination_port}/{protocol}")
        self.detector.record_network_connection(
            source_ip=source_ip,
            destination_port=destination_port,
            protocol=protocol,
            is_test=is_test
        )

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
                self.handle_probe(src_ip, port, protocol="TCP")
                client_sock.close()
            except Exception as e:
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
                "-e", "ip.src",
                "-e", "tcp.dstport"
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
        tcpdump_regex = re.compile(r"IP\s+(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s*>\s*(\d{1,3}(?:\.\d{1,3}){3})\.(\d+):\s*Flags\s*\[(.*?)\]")

        for line in self._proc.stdout:
            if not self.running:
                break
            line_str = line.strip()
            if not line_str:
                continue

            # TShark format: <ip.src>\t<tcp.dstport>
            if "\t" in line_str:
                parts = line_str.split("\t")
                if len(parts) >= 2:
                    try:
                        src_ip = parts[0].strip()
                        dst_port = int(parts[1].strip())
                        self.handle_probe(src_ip, dst_port, protocol="TCP")
                    except ValueError:
                        continue
            # Tcpdump format: 10:34:56.923614 enp0s8 In IP 192.168.31.204.59286 > 192.168.31.91.5000: Flags [S]
            else:
                match = tcpdump_regex.search(line_str)
                if match:
                    src_ip = match.group(1)
                    dst_ip = match.group(3)
                    dst_port = int(match.group(4))
                    flags = match.group(5)
                    
                    target_ip = os.getenv("CN_SERVER_IP")
                    if target_ip and dst_ip != target_ip:
                        continue
                    
                    if "S" in flags and "." not in flags:
                        self.handle_probe(src_ip, dst_port, protocol="TCP")

    def start(self):
        """Start sniffer engine (pcap + canary listeners)."""
        self.running = True
        self.start_pcap_engine()
        self.start_canary_listeners()
        print("[*] [SNIFFER] Network telemetry monitoring operational.")

    def stop(self):
        """Stop all sniffer threads and listeners."""
        self.running = False
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception as e:
                print(f"[-] [SNIFFER] Warning terminating pcap proc: {e}")
        for s in self._sockets:
            try:
                s.close()
            except Exception as e:
                print(f"[-] [SNIFFER] Warning closing socket: {e}")
        self._sockets.clear()
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
    print("  SOC AUTH     = [CONFIGURED]")

    print(f"[*] Starting Protected Web Server Network Sniffer -> {soc_url}")
    sniffer = NetworkSniffer(soc_url=soc_url, api_key=api_key)
    sniffer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()

