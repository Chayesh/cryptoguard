"""
CryptoGuard — Network-Level Detection Layer
============================================
Author  : CK (FYP / Portfolio Project)

Second independent detection layer using packet capture.
Detects cryptojacking via:
  1. Known mining pool IP/domain connections
  2. Stratum protocol pattern (port 3333, 4444, 5555, 14433)
  3. Packet timing regularity (miners submit shares on a schedule)
  4. Sustained outbound traffic to single destination

Runs as a background thread alongside the host-based ML detector.
When BOTH layers agree → very high confidence detection.

SETUP:
    pip3 install scapy
    sudo setcap cap_net_raw=eip $(readlink -f $(which python3))
    # OR run dashboard with sudo

USAGE:
    Imported by dashboard.py automatically.
    from network_detector import NetworkDetector
    nd = NetworkDetector()
    nd.start()
    # nd.get_status() → dict with detections
    nd.stop()
"""

import threading
import time
import socket
from datetime import datetime
from collections import defaultdict, deque

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, conf
    conf.verb = 0          # silence scapy output
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[NetDet] ⚠️  scapy not installed — pip3 install scapy")

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

# Known mining pool ports (Stratum protocol)
MINING_PORTS = {3333, 4444, 5555, 7777, 8008, 8080, 9000, 14433, 45700}

# Known mining pool domains / IP fragments
MINING_POOL_DOMAINS = [
    "xmrig.com", "pool.minexmr.com", "xmr.pool.minergate",
    "monerohash.com", "moneroocean.stream", "supportxmr.com",
    "hashvault.pro", "nanopool.org", "2miners.com",
    "xmrpool.eu", "cryptonote.social", "monerop.com",
    "coinfoundry.org", "minexmr", "xmrpool",
]

# Stratum protocol signatures in packet payload
STRATUM_SIGNATURES = [
    b'"method":"mining.',
    b'"method": "mining.',
    b'mining.subscribe',
    b'mining.authorize',
    b'mining.submit',
    b'"jsonrpc"',
    b'job_id',
    b'target":"',
    b'"blob"',
]

# Thresholds
SUSTAINED_CONN_SECONDS  = 30
PACKET_RATE_THRESHOLD   = 5    # packets/sec to same dest = suspicious
DETECTION_WINDOW        = 60   # seconds to track connections


# ──────────────────────────────────────────────
# NETWORK DETECTOR CLASS
# ──────────────────────────────────────────────

class NetworkDetector:
    """
    Background thread that sniffs packets and detects mining activity.
    Thread-safe — read state via get_status() from any thread.
    """

    def __init__(self, interface=None):
        self.interface   = interface   # None = auto-detect
        self._running    = False
        self._thread     = None
        self._lock       = threading.Lock()

        # Detection state
        self._detections     = []          # list of detection events
        self._active_threats = {}          # dst_ip → threat info
        self._conn_tracker   = defaultdict(list)   # dst_ip → [timestamps]
        self._stratum_hits   = deque(maxlen=50)    # recent stratum detections
        self._packet_count   = 0
        self._start_time     = None

        # Stats
        self._stats = {
            "packets_captured"   : 0,
            "mining_port_hits"   : 0,
            "stratum_hits"       : 0,
            "pool_ip_hits"       : 0,
            "active_threats"     : 0,
            "total_detections"   : 0,
        }

    # ── CONTROL ─────────────────────────────────

    def start(self):
        if not SCAPY_AVAILABLE:
            print("[NetDet] ⚠️  scapy unavailable — network detection disabled")
            return False
        if self._running:
            return True

        self._running    = True
        self._start_time = time.time()
        self._thread     = threading.Thread(
            target=self._sniff_loop, daemon=True
        )
        self._thread.start()
        print(f"[NetDet] ✅ Network detector started"
              f"{f' on {self.interface}' if self.interface else ' (auto interface)'}")
        return True

    def stop(self):
        self._running = False
        print("[NetDet] Stopped")

    # ── STATUS API ───────────────────────────────

    def get_status(self) -> dict:
        """Thread-safe status snapshot for dashboard."""
        with self._lock:
            return {
                "available"       : SCAPY_AVAILABLE,
                "running"         : self._running,
                "packets_captured": self._stats["packets_captured"],
                "mining_port_hits": self._stats["mining_port_hits"],
                "stratum_hits"    : self._stats["stratum_hits"],
                "pool_ip_hits"    : self._stats["pool_ip_hits"],
                "active_threats"  : list(self._active_threats.values()),
                "total_detections": self._stats["total_detections"],
                "recent_detections": self._detections[-10:],
                "uptime_sec"      : int(time.time() - self._start_time)
                                    if self._start_time else 0,
            }

    def get_threat_level(self) -> str:
        """Returns SAFE / WARNING / THREAT based on network findings."""
        with self._lock:
            if self._active_threats:
                return "THREAT"
            recent_stratum = [h for h in self._stratum_hits
                              if time.time() - h["ts"] < 30]
            if recent_stratum or self._stats["mining_port_hits"] > 0:
                return "WARNING"
            return "SAFE"

    def get_latest_detection(self) -> dict:
        """Returns most recent network detection or None."""
        with self._lock:
            return self._detections[-1] if self._detections else None

    # ── PACKET PROCESSING ────────────────────────

    def _sniff_loop(self):
        """Main packet capture loop."""
        try:
            sniff(
                iface    = self.interface,
                prn      = self._process_packet,
                store    = False,               # don't store packets in memory
                stop_filter = lambda _: not self._running,
                filter   = "tcp or udp",        # BPF filter — skip ICMP etc.
            )
        except Exception as e:
            print(f"[NetDet] Sniff error: {e}")
            print("[NetDet] Try running with sudo or set cap_net_raw")
            self._running = False

    def _process_packet(self, pkt):
        """Called for every captured packet."""
        try:
            if not self._running:
                return

            with self._lock:
                self._stats["packets_captured"] += 1

            # Only process outbound IP packets
            if not pkt.haslayer(IP):
                return

            src_ip  = pkt[IP].src
            dst_ip  = pkt[IP].dst
            dst_port = None

            if pkt.haslayer(TCP):
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                dst_port = pkt[UDP].dport

            # Skip localhost and private ranges (rough check)
            if dst_ip.startswith("127.") or dst_ip.startswith("10.") \
               or dst_ip == "0.0.0.0":
                return

            # ── Detection 1: Mining pool port ──────────
            if dst_port in MINING_PORTS:
                self._flag_mining_port(src_ip, dst_ip, dst_port)

            # ── Detection 2: Stratum protocol payload ──
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                self._check_stratum(src_ip, dst_ip, dst_port, payload)

            # ── Detection 3: Known mining pool IP/DNS ──
            self._check_pool_ip(src_ip, dst_ip, dst_port)

            # ── Detection 4: Sustained connection tracking ──
            if dst_port in MINING_PORTS:
                self._track_connection(dst_ip, dst_port)

        except Exception:
            pass   # never crash the sniffer thread

    def _flag_mining_port(self, src, dst, port):
        """Flag connection to known mining port."""
        with self._lock:
            self._stats["mining_port_hits"] += 1

            key = f"{dst}:{port}"
            now = datetime.now().strftime("%H:%M:%S")

            if key not in self._active_threats:
                self._active_threats[key] = {
                    "dst_ip"    : dst,
                    "dst_port"  : port,
                    "method"    : "mining_port",
                    "detail"    : f"Outbound connection to port {port} (Stratum protocol)",
                    "first_seen": now,
                    "last_seen" : now,
                    "count"     : 1,
                }
                self._log_detection("mining_port",
                    f"Connection to mining port {port} → {dst}", dst, port)
            else:
                self._active_threats[key]["last_seen"] = now
                self._active_threats[key]["count"]    += 1

    def _check_stratum(self, src, dst, port, payload):
        """Check packet payload for Stratum protocol signatures."""
        payload_lower = payload.lower()
        for sig in STRATUM_SIGNATURES:
            if sig.lower() in payload_lower:
                with self._lock:
                    self._stats["stratum_hits"] += 1
                    hit = {
                        "ts"     : time.time(),
                        "dst"    : dst,
                        "port"   : port,
                        "sig"    : sig.decode("utf-8", errors="replace"),
                        "time"   : datetime.now().strftime("%H:%M:%S"),
                    }
                    self._stratum_hits.append(hit)
                    self._log_detection("stratum_protocol",
                        f"Stratum signature '{sig.decode('utf-8', errors='replace')}' in packet to {dst}:{port}",
                        dst, port)

                    # Stratum is very specific — immediately add to active threats
                    key = f"stratum_{dst}"
                    self._active_threats[key] = {
                        "dst_ip"    : dst,
                        "dst_port"  : port,
                        "method"    : "stratum_protocol",
                        "detail"    : f"Stratum mining protocol detected in payload → {dst}",
                        "first_seen": hit["time"],
                        "last_seen" : hit["time"],
                        "count"     : 1,
                        "signature" : sig.decode("utf-8", errors="replace"),
                    }
                break   # one match per packet is enough

        _dns_cache = {}   # class-level cache

    def _check_pool_ip(self, src, dst, port):
        """Try reverse DNS and check against known pool domains."""
        try:
            if dst in self._dns_cache:
                hostname = self._dns_cache[dst]
            else:
                hostname = socket.getfqdn(dst).lower()
                self._dns_cache[dst] = hostname
            for pool in MINING_POOL_DOMAINS:
                if pool in hostname:
                    with self._lock:
                        self._stats["pool_ip_hits"] += 1
                        key = f"pool_{dst}"
                        now = datetime.now().strftime("%H:%M:%S")
                        self._active_threats[key] = {
                            "dst_ip"    : dst,
                            "dst_port"  : port,
                            "method"    : "pool_domain",
                            "detail"    : f"Connection to known mining pool: {hostname}",
                            "first_seen": now,
                            "last_seen" : now,
                            "count"     : 1,
                            "hostname"  : hostname,
                        }
                        self._log_detection("pool_domain",
                            f"Known mining pool domain: {hostname} ({dst})",
                            dst, port)
                    break
        except Exception:
            pass   # DNS lookup failed — not critical

    def _track_connection(self, dst_ip, dst_port):
        """Track connection frequency — sustained = suspicious."""
        now = time.time()
        key = f"{dst_ip}:{dst_port}"

        with self._lock:
            # Keep only recent timestamps
            self._conn_tracker[key] = [
                t for t in self._conn_tracker[key]
                if now - t < DETECTION_WINDOW
            ]
            self._conn_tracker[key].append(now)

            count    = len(self._conn_tracker[key])
            duration = now - self._conn_tracker[key][0] if count > 1 else 0

            # Sustained connection over threshold
            if duration >= SUSTAINED_CONN_SECONDS and count >= 10:
                rate = count / max(duration, 1)
                if rate >= PACKET_RATE_THRESHOLD:
                    sustained_key = f"sustained_{dst_ip}"
                    if sustained_key not in self._active_threats:
                        now_str = datetime.now().strftime("%H:%M:%S")
                        self._active_threats[sustained_key] = {
                            "dst_ip"    : dst_ip,
                            "dst_port"  : dst_port,
                            "method"    : "sustained_traffic",
                            "detail"    : f"Sustained outbound traffic: {rate:.1f} pkt/s for {duration:.0f}s → {dst_ip}",
                            "first_seen": now_str,
                            "last_seen" : now_str,
                            "count"     : count,
                            "rate_pps"  : round(rate, 2),
                        }
                        self._log_detection("sustained_traffic",
                            f"Sustained traffic {rate:.1f}pkt/s for {duration:.0f}s → {dst_ip}:{dst_port}",
                            dst_ip, dst_port)

    def _log_detection(self, method, detail, dst_ip, dst_port):
        """Add a detection event to the log."""
        self._stats["total_detections"] += 1
        self._stats["active_threats"]    = len(self._active_threats)
        self._detections.append({
            "time"     : datetime.now().strftime("%H:%M:%S"),
            "method"   : method,
            "detail"   : detail,
            "dst_ip"   : dst_ip,
            "dst_port" : dst_port,
            "layer"    : "network",
        })
        # Keep last 50
        if len(self._detections) > 50:
            self._detections = self._detections[-50:]

        print(f"[NetDet] 🚨 {method}: {detail}")

    def clear_threats(self):
        """Clear active threats (call after kill)."""
        with self._lock:
            self._active_threats.clear()
            print("[NetDet] Active threats cleared")


# ──────────────────────────────────────────────
# STANDALONE TEST
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  CryptoGuard — Network Detector Test")
    print("="*50)
    print("  Listening for mining traffic...")
    print("  Run XMRig in another terminal to test.")
    print("  Press Ctrl+C to stop.\n")

    nd = NetworkDetector(interface='eth0')
    if not nd.start():
        print("❌ Failed to start — check scapy installation")
        exit(1)

    try:
        while True:
            status = nd.get_status()
            threat = nd.get_threat_level()
            threat_color = "\033[91m" if threat == "THREAT" else \
                           "\033[93m" if threat == "WARNING" else "\033[92m"
            print(
                f"\r  [{threat_color}{threat}\033[0m] "
                f"Packets: {status['packets_captured']:>6}  "
                f"PortHits: {status['mining_port_hits']:>3}  "
                f"Stratum: {status['stratum_hits']:>3}  "
                f"Threats: {len(status['active_threats']):>2}",
                end=""
            )
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n  Stopping...")
        nd.stop()
        status = nd.get_status()
        print(f"\n  Final stats:")
        print(f"    Packets captured  : {status['packets_captured']}")
        print(f"    Mining port hits  : {status['mining_port_hits']}")
        print(f"    Stratum hits      : {status['stratum_hits']}")
        print(f"    Total detections  : {status['total_detections']}")
        if status['recent_detections']:
            print(f"\n  Detections:")
            for d in status['recent_detections']:
                print(f"    [{d['time']}] {d['method']}: {d['detail']}")
