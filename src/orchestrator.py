import time
import json
import threading
from collections import defaultdict
from pathlib import Path
from tshark_wrapper import capture_to_pcap
from packet_to_flow import pcap_to_flows
from ml.model import EnsembleModel
from risk import risk_score
from defender import Defender
import socket
import struct
import urllib.request

ALERTS_FILE = Path('alerts.json')

def get_interface_ip(iface: str) -> str:
    # Helper to get the actual local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        res = s.getsockname()[0]
        s.close()
        return res
    except Exception:
        return "192.168.1.1"

def get_default_gateway() -> str:
    # Discovery of the local gateway (router)
    try:
        import subprocess
        res = subprocess.run(["netstat", "-rn"], capture_output=True, text=True)
        for line in res.stdout.split('\n'):
            if 'default' in line:
                return line.split()[1]
    except Exception:
        pass
    return "192.168.1.1"

SIEM_LOG = Path('isdnf_siem.log')

def log_to_siem(alert: dict):
    # Wazuh-compatible single-line JSON logging
    try:
        with open(SIEM_LOG, 'a') as f:
            f.write(json.dumps(alert) + '\n')
    except Exception:
        pass

class PulseMonitor:
    def __init__(self, iface):
        self.iface = iface
        self.pkt_count = 0
        self.byte_count = 0
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def start(self):
        import subprocess
        # Use tcpdump for lightweight ingress counting
        cmd = ["sudo", "tcpdump", "-i", self.iface, "-l", "-n", "-e"]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        threading.Thread(target=self._run, daemon=True).start()
        threading.Thread(target=self._broadcaster, daemon=True).start()

    def _run(self):
        for line in self.proc.stdout:
            if self.stop_event.is_set(): break
            # Each line is a packet. Approximate byte count from 'length' field in -e output
            with self.lock:
                self.pkt_count += 1
                if 'length' in line:
                    try:
                        self.byte_count += int(line.split('length ')[1].split(':')[0])
                    except: self.byte_count += 64

    def _broadcaster(self):
        while not self.stop_event.is_set():
            time.sleep(0.2) # Update every 200ms for ultra-low latency
            with self.lock:
                stats = {
                    "type": "pulse",
                    "pps": self.pkt_count * 5,
                    "bps": self.byte_count * 5,
                    "time": time.time()
                }
                self.pkt_count = 0
                self.byte_count = 0
            
            try:
                req = urllib.request.Request("http://127.0.0.1:5010/events", 
                                          data=json.dumps(stats).encode(),
                                          headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req)
            except: pass

def is_spoofed(ip: str, iface_ip: str) -> bool:
    # RFC-1918 Private Ranges
    def is_private(addr: str) -> bool:
        try:
            p = addr.split('.')
            if len(p) != 4: return False
            p0, p1 = int(p[0]), int(p[1])
            if p0 == 10: return True
            if p0 == 172 and (16 <= p1 <= 31): return True
            if p0 == 192 and p1 == 168: return True
            return False
        except: return False

    # If the source is a PUBLIC IP (e.g. Datacenter), it cannot be "spoofed" 
    # in the context of our local segment mismatch logic.
    if not is_private(ip):
        return False

    # For Private IPs, verify they belong to the same local segment
    iface_parts = iface_ip.split(".")
    ip_parts = ip.split(".")
    if len(iface_parts) < 2 or len(ip_parts) < 2:
        return False
    # Flag if the first two octets of the private range don't match our local network
    return iface_parts[0] != ip_parts[0] or iface_parts[1] != ip_parts[1]

def append_alert(alert: dict):
    try:
        req = urllib.request.Request("http://127.0.0.1:5010/events", data=json.dumps(alert).encode(), headers={'Content-Type': 'application/json'}, method='POST')
        urllib.request.urlopen(req, timeout=0.5)
        return
    except Exception:
        pass

    # Fallback if dashboard is not running
    arr = []
    if ALERTS_FILE.exists():
        try:
            arr = json.loads(ALERTS_FILE.read_text())
        except Exception:
            arr = []
    arr.append(alert)
    ALERTS_FILE.write_text(json.dumps(arr, indent=2))

def flush_loop(defender: Defender):
    while True:
        flushed = defender.flush_expired_rules()
        if flushed:
            print(f"Flushed expired rules: {flushed}")
        time.sleep(60)

def run_cycle(interface: str = 'en0', duration: int = 10, model_path: str = 'models/ensemble_model.joblib', dry_run=True):
    iface_ip = get_interface_ip(interface)
    defender = Defender(dry_run=dry_run)
    
    # Start flush thread
    threading.Thread(target=flush_loop, args=(defender,), daemon=True).start()

    # Intelligence Layer: Persistent Threat Memory
    iface_ip = get_interface_ip(interface)
    gateway_ip = get_default_gateway()
    
    # Start Real-time Ingress Pulse Monitor
    pulse = PulseMonitor(interface)
    pulse.start()

    print(f"ISDNF Autonomous SOC Active on {interface} ({iface_ip})")
    print(f"Infrastructure Discovery: Gateway identified at {gateway_ip}")
    
    # Auto-Whitelist Local Stack
    defender.add_to_whitelist(ip=iface_ip)
    defender.add_to_whitelist(ip=gateway_ip)
    
    threat_memory = defaultdict(int)
    
    while True:
        # Dynamic Whitelist Reload
        defender.load_whitelist()
        
        cap_dir = Path('captures')
        cap_dir.mkdir(exist_ok=True)
        pcap = str(cap_dir / f'capture_{int(time.time())}.pcap')
        
        try:
            capture_to_pcap(interface, duration, pcap)

            flows_csv = str(cap_dir / (Path(pcap).stem + '.flows.csv'))
            pcap_to_flows(pcap, flows_csv)

            model = EnsembleModel()
            model.load(model_path)
            import pandas as pd
            df = pd.read_csv(flows_csv)
            if df.empty:
                continue
            
            scores = model.score(df)
            df['anomaly'] = scores

            # Aggregate risk per source IP instead of per individual port-flow
            for ip, group in df.groupby('src_ip'):
                if defender.is_protected(ip):
                    continue
                    
                # Attack intensity is the sum of all packets across all flows from this IP
                pkt = int(group['packet_count'].sum())
                b = int(group['byte_count'].sum())
                # Anomaly is the most anomalous behavior seen across any of their flows
                anomaly = float(group['anomaly'].max())
                
                # Persistence Check (Stateful Memory)
                persistence = threat_memory[ip]

                # Multi-dimensional metadata for Hybrid Defense
                unique_ports = group['dst_port'].nunique()
                observed_ports = group['dst_port'].unique().tolist()
                is_standard = any(p in [443, 80, 53, 8080, 8443, 22] for p in observed_ports)
                is_infra = (ip == iface_ip or ip == gateway_ip)
                
                meta = {
                    "unique_ports_count": unique_ports,
                    "dst_ports": observed_ports,
                    "is_standard_service": is_standard,
                    "is_local_infrastructure": is_infra
                }

                # Multi-Dimensional Risk Scoring
                assessment = risk_score(anomaly, pkt, b, persistence=persistence, metadata=meta)
                
                # Spoofing Detection Logic (Risk Elevation)
                is_spoof = is_spoofed(ip, iface_ip)
                if is_spoof:
                    assessment["score"] = min(100.0, assessment["score"] * 1.5)
                    if assessment["score"] >= 85: assessment["action"] = "BLOCK"

                r = assessment["score"]
                action = assessment["action"]

                threat_memory[ip] += 1
                
                block_res = "LOGGED"
                if action == "BLOCK":
                    print(f'Tactical Threat: {ip} | Risk: {r:.1f} | Action: {action}')
                    block_res_dict = defender.block_ip(ip)
                    block_res = block_res_dict.get("status", "error")
                elif action == "RATE_LIMIT":
                    print(f'Throttling Traffic: {ip} | Risk: {r:.1f} | Action: {action}')
                    limit_res = defender.throttle_ip(ip, rate_kbps=100)
                    block_res = limit_res.get("status", "error")
                
                alert = {
                    'time': time.time(),
                    'src_ip': ip,
                    'risk': r,
                    'anomaly': anomaly,
                    'persistence': persistence,
                    'spoofed': is_spoof,
                    'breakdown': assessment["breakdown"],
                    'action': action,
                    'status': block_res,
                    'meta': meta
                }
                append_alert(alert)
                log_to_siem(alert)
        except Exception as e:
            print(f"Cycle Error: {e}")
            time.sleep(5)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', default='en0')
    parser.add_argument('--duration', type=int, default=10)
    parser.add_argument('--model', default='models/ensemble_model.joblib')
    parser.add_argument('--no-dry-run', dest='dry', action='store_false')
    args = parser.parse_args()
    run_cycle(args.iface, args.duration, args.model, dry_run=args.dry)
