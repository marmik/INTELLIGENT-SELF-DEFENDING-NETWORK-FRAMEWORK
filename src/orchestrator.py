import time
import json
import subprocess
import os
from pathlib import Path
from collections import defaultdict
import ipaddress
from ml.high_perf_model import HighPerfInferenceEngine
import numpy as np
import pandas as pd
import threading
from pathlib import Path
from tshark_wrapper import capture_to_pcap
from packet_to_flow import pcap_to_flows
from ml.model import EnsembleModel
from risk import risk_score
from defender import Defender
import socket
import struct
import urllib.request
import geocoder
import psutil
from ml.high_perf_model import HighPerfInferenceEngine

GLOBAL_DASHBOARD_URL = "http://127.0.0.1:5010/events"
GEO_CACHE = {} # IP -> GeoData
GEO_LOCK = threading.Lock()

def get_ip_geo(ip: str):
    """Resolves IP to Lat/Lon with local caching for V15.0 Map."""
    if ip.startswith(('192.168.', '10.', '127.', '172.')):
        return None
    with GEO_LOCK:
        if ip in GEO_CACHE: return GEO_CACHE[ip]
    try:
        g = geocoder.ip(ip)
        if g.ok:
            data = {"lat": g.latlng[0], "lon": g.latlng[1], "country": g.country}
            with GEO_LOCK: GEO_CACHE[ip] = data
            return data
    except: pass
    return None

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
        self.global_pkt_count = 0 # Persistent global count
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def start(self):
        import subprocess
        # Try tcpdump first (lightweight), then fallback to tshark
        try:
            cmd = ["tcpdump", "-i", self.iface, "-l", "-n", "-e"]
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # Check if it fails immediately (e.g. permission)
            time.sleep(0.5)
            if self.proc.poll() is not None:
                raise Exception("tcpdump failed")
        except:
            cmd = ["tshark", "-i", self.iface, "-l", "-T", "fields", "-e", "frame.len"]
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        
        threading.Thread(target=self._run, daemon=True).start()
        threading.Thread(target=self._broadcaster, daemon=True).start()

    def _run(self):
        for line in self.proc.stdout:
            if self.stop_event.is_set(): break
            line = line.strip()
            if not line: continue
            
            with self.lock:
                self.pkt_count += 1
                self.global_pkt_count += 1
                
                # Case 1: TShark field output (just the length)
                if line.isdigit():
                    self.byte_count += int(line)
                # Case 2: Tcpdump -e output (contains 'length X:')
                elif 'length' in line:
                    try:
                        self.byte_count += int(line.split('length ')[1].split(':')[0])
                    except: self.byte_count += 64
                else:
                    self.byte_count += 64

    def _broadcaster(self):
        import psutil
        while not self.stop_event.is_set():
            time.sleep(0.2) # Update every 200ms for ultra-low latency
            with self.lock:
                # Get Hardware Stats (psutil.cpu_percent is non-blocking with interval=None)
                cpu_load = psutil.cpu_percent(interval=None)
                ram_usage = psutil.virtual_memory().percent
                
                # Heuristic for Temperature on macOS M2 (since direct access is restricted)
                # We'll use a mix of load and a baseline to simulate the "Stress" feel accurately
                temp_base = 35.0
                thermal_load = (cpu_load * 0.4) + (ram_usage * 0.1)
                system_temp = temp_base + thermal_load

                stats = {
                    "type": "pulse",
                    "pps": self.pkt_count * 5,
                    "bps": self.byte_count * 5,
                    "global_total": self.global_pkt_count,
                    "cpu_load": cpu_load,
                    "ram_usage": ram_usage,
                    "system_temp": system_temp,
                    "time": time.time()
                }
                self.pkt_count = 0
                self.byte_count = 0
            
            try:
                req = urllib.request.Request(GLOBAL_DASHBOARD_URL, 
                                          data=json.dumps(stats).encode(),
                                          headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req, timeout=0.1)
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

class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (np.int64, np.int32, np.float64, np.float32)):
            return obj.item()
        return super().default(obj)

def append_alert(alert: dict):
    try:
        data = json.dumps(alert, cls=NumpyEncoder).encode()
        req = urllib.request.Request(GLOBAL_DASHBOARD_URL, data=data, 
                                    headers={'Content-Type': 'application/json'}, method='POST')
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
    ALERTS_FILE.write_text(json.dumps(arr, indent=2, cls=NumpyEncoder))

def flush_loop(defender: Defender):
    while True:
        flushed = defender.flush_expired_rules()
        if flushed:
            print(f"Flushed expired rules: {flushed}")
        time.sleep(60)

def run_cycle(
    interface: str = 'en0',
    duration: int = 10,
    model_path: str = 'models/ensemble_model.joblib',
    dry_run=True,
    honeypot_ip: str = '127.0.0.1',
    honeypot_port: int = 8080,
):
    iface_ip = get_interface_ip(interface)
    defender = Defender(
        dry_run=dry_run,
        iface=interface,
        honeypot_ip=honeypot_ip,
        honeypot_port=honeypot_port,
    )
    
    # Start flush thread
    threading.Thread(target=flush_loop, args=(defender,), daemon=True).start()

    # Intelligence Layer: Persistent Threat Memory
    iface_ip = get_interface_ip(interface)
    gateway_ip = get_default_gateway()
    
    # Start Real-time Ingress Pulse Monitor
    pulse = PulseMonitor(interface)
    pulse.start()

    mode = "DRY-RUN" if dry_run else "ACTIVE-ENFORCEMENT"
    print(f"ISDNF Autonomous SOC Active on {interface} ({iface_ip}) [{mode}]")
    print(f"Infrastructure Discovery: Gateway identified at {gateway_ip}")
    
    # Auto-Whitelist Local Stack
    defender.add_to_whitelist(ip=iface_ip)
    defender.add_to_whitelist(ip=gateway_ip)
    
    # Auto-Whitelist entire local subnet (RFC-1918 private ranges)
    # This prevents false positives on your local network devices
    local_subnets = [
        '192.168.0.0/16',    # Class C private
        '10.0.0.0/8',        # Class A private
        '172.16.0.0/12'      # Class B private
    ]
    for subnet in local_subnets:
        # Bypass the netmask check by adding a few sample IPs from the subnet
        pass  # defender.is_protected() will handle the CIDR check anyway
    
    threat_memory = defaultdict(int)
    
    # Initialize high-performance model once
    model = HighPerfInferenceEngine()
    
    # Multi-Interface Auto-Discovery (V15.0)
    interfaces = [interface]
    # Check if bridge100 or bridge0 exists for VMs
    try:
        chk_bridge = subprocess.run(["ifconfig", "bridge100"], capture_output=True, text=True)
        if chk_bridge.returncode == 0:
            interfaces.append("bridge100")
            print(f"Adding bridge100 to capture set for VM visibility.", flush=True)
    except:
        pass

    print(f"ISDNF Autonomous SOC Active on {interfaces} ({iface_ip})", flush=True)
    
    cap_dir = Path('captures')
    cap_dir.mkdir(exist_ok=True)
    # Global state for adaptive learning (V16.6)
    threat_memory = defaultdict(int)
    ip_stability = defaultdict(int) # Tracks consecutive benign cycles
    BASELINE_PATH = "models/benign_baseline.csv"
    
    # Initialize high-performance model once
    model = HighPerfInferenceEngine()
    
    # Concepts for Operational Intelligence (V16.0)
    anomaly_history = []
    DRIFT_WINDOW = 100

    # Reduce dashboard flood: suppress repeated alerts for the same source/action
    # unless action changes, risk changes materially, or cooldown expires.
    alert_cooldowns = {
        "DECEIVE": 30,
        "CRITICAL_BLOCK": 30,
        "BLOCK": 20,
        "RATE_LIMIT": 25,
        "LOG": 45,
    }
    last_alert_state = {}
    
    while True:
        # Dynamic Whitelist Reload
        defender.load_whitelist()
        
        pcap = str(cap_dir / f'capture_{int(time.time())}.pcap')
        
        try:
            print(f"\n--- SOC CYCLE START: {pcap} ---", flush=True)
            capture_to_pcap(interfaces, duration, pcap)
            

            flows_csv = str(cap_dir / (Path(pcap).stem + '.flows.csv'))
            pcap_to_flows(pcap, flows_csv)

            df = pd.read_csv(flows_csv)
            if df.empty:
                print("No traffic detected. Skipping cycle.", flush=True)
                continue

            print(f"Running Hybrid ML Inference on {len(df)} flows...", flush=True)
            try:
                cal_scores, raw_scores, labels, payload_scores = model.predict(df)
                df['anomaly'] = cal_scores
                df['raw_anomaly'] = raw_scores
                df['classification'] = labels
                df['payload_score'] = payload_scores

                # Concept Drift Detection (using calibrated scores)
                avg_anomaly = np.mean(cal_scores)
                anomaly_history.append(avg_anomaly)
                if len(anomaly_history) > DRIFT_WINDOW:
                    old_avg = np.mean(anomaly_history[-DRIFT_WINDOW:-DRIFT_WINDOW//2])
                    new_avg = np.mean(anomaly_history[-DRIFT_WINDOW//2:])
                    if abs(new_avg - old_avg) > 0.3:
                        print(f"!!! ALERT: Concept Drift Detected (Shift: {new_avg - old_avg:.2f}) !!!")
                
            except Exception as ml_e:
                print(f"ML PREDICTION FAILED: {ml_e}", flush=True)
                df['anomaly'] = 0.5 
                df['raw_anomaly'] = 0.5
                df['classification'] = 'ENGINE_ERROR'
                df['payload_score'] = 0.0

            print(f"Grouping and Assessing Risk for {df['src_ip'].nunique()} source IPs...", flush=True)
            for ip, group in df.groupby('src_ip'):
                if defender.is_protected(ip): continue
                    
                pkt = int(group['packet_count'].sum())
                b = int(group['byte_count'].sum())
                
                # Signal Averaging (V16.3) to ignore single-packet noise
                # 0.7*mean + 0.3*max blend
                anomaly = float(0.7 * group['anomaly'].mean() + 0.3 * group['anomaly'].max())
                payload_prob = float(0.7 * group['payload_score'].mean() + 0.3 * group['payload_score'].max())
                
                persistence = threat_memory[ip]
                unique_ports = group['dst_port'].nunique()
                observed_ports = group['dst_port'].unique().tolist()
                src_mac = group['src_mac'].iloc[0] if 'src_mac' in group else "00:00:00:00:00:00"
                syn_flags = int(group['SYN Flag Count'].sum()) if 'SYN Flag Count' in group else 0
                ack_flags = int(group['ACK Flag Count'].sum()) if 'ACK Flag Count' in group else 0
                rst_flags = int(group['RST Flag Count'].sum()) if 'RST Flag Count' in group else 0
                incomplete_handshakes = max(0, syn_flags - (ack_flags + rst_flags))
                
                from ml.utils import is_known_infra
                
                meta = {
                    "unique_ports_count": unique_ports,
                    "dst_ports": observed_ports[:20], 
                    "is_local_infrastructure": (ip == iface_ip or ip == gateway_ip),
                    "is_datacenter": is_known_infra(ip),
                    "model_classification": str(group['classification'].iloc[0]),
                    "src_mac": src_mac,
                    "incomplete_handshakes": incomplete_handshakes,
                    "flow_duration_max": group['Flow Duration'].max(),
                    "adaptive_scaling": model.calibrator.get_adaptive_scaling(),
                    "payload_score": payload_prob
                }

                # Multi-Dimensional Weighted Risk Scoring
                assessment = risk_score(anomaly, pkt, b, persistence=persistence, 
                                        metadata=meta)
                
                r = assessment["score"]
                action = assessment["action"]
                classification = str(meta.get("model_classification", "")).upper()
                strong_scan_ioc = (
                    unique_ports >= 12
                    or incomplete_handshakes >= 6
                    or classification in {"PORTSCAN", "RECON", "RECONNAISSANCE"}
                )
                rapid_scan_ioc = (
                    unique_ports >= 8
                    and (
                        incomplete_handshakes >= 4
                        or syn_flags >= 10
                    )
                )
                strong_payload_ioc = payload_prob >= 0.92 and anomaly >= 0.9
                has_strong_ioc = strong_scan_ioc or strong_payload_ioc
                has_behavioral_support = has_strong_ioc or persistence >= 4
                is_private_ip = False
                try:
                    is_private_ip = ipaddress.ip_address(ip).is_private
                except ValueError:
                    is_private_ip = False
                
                # Smart Threat Memory - Conditional Persistence & Decay (V16.5)
                is_infra_ip = meta.get("is_datacenter", False)
                
                # datacenter addresses are deliberately given an "immune" posture
                # because they are very common on the public internet and often
                # represent legitimate services.  the risk_score() already halves
                # their score, but we take one more precaution: never escalate
                # beyond LOG unless the calculated score is extremely high.
                if is_infra_ip:
                    # keep persistence decay faster so the ip doesn't accumulate
                    # stale history, but lower the actual action to logging
                    if r < 20:
                        threat_memory[ip] = max(0, threat_memory[ip] - 2)
                    else:
                        # don't treat a cloud IP as an automatic block
                        action = "LOG"

                    # keep dashboard severity at NORMAL for infra traffic unless
                    # we also have strong IoCs (scan behavior or highly malicious payload).
                    if not (strong_scan_ioc or strong_payload_ioc):
                        r = min(r, 39.0)
                else:
                    # Only let memory increase when elevated risk is backed by
                    # strong evidence. This avoids false-positive escalation loops.
                    if r > 40 and (has_strong_ioc or incomplete_handshakes >= 3):
                        threat_memory[ip] += 1
                    elif r < 20:
                        threat_memory[ip] = max(0, threat_memory[ip] - 1)

                # Evidence gate for active mitigation:
                # Do not block/deceive on score alone. Require strong IoCs or
                # persistent suspicious behavior before escalating above RATE_LIMIT.
                if action in {"CRITICAL_BLOCK", "BLOCK", "DECEIVE"} and not has_behavioral_support:
                    if r >= 55 or payload_prob > 0.5:
                        action = "RATE_LIMIT"
                        r = min(r, 69.0)
                    else:
                        action = "LOG"
                        r = min(r, 39.0)

                # Private/internal addresses should be treated conservatively.
                # Keep them visible, but avoid hard blocks unless attack IoCs are clear.
                if is_private_ip and not has_strong_ioc and action in {"CRITICAL_BLOCK", "BLOCK", "DECEIVE"}:
                    action = "RATE_LIMIT" if r >= 50 else "LOG"
                    r = min(r, 69.0 if action == "RATE_LIMIT" else 39.0)

                # Noise suppression for demo stability:
                # if RATE_LIMIT has no strong IoCs and low payload confidence,
                # downgrade to LOG so normal traffic is shown as NORMAL.
                if (
                    action == "RATE_LIMIT"
                    and not has_strong_ioc
                    and payload_prob < 0.55
                    and unique_ports <= 3
                    and incomplete_handshakes <= 1
                ):
                    action = "LOG"
                    r = min(r, 34.0)

                # Fast-path escalation for explicit scanning behavior so active
                # blocking happens in the next short capture window.
                if (not is_infra_ip) and strong_scan_ioc and action in {"LOG", "RATE_LIMIT"}:
                    action = "BLOCK"
                    r = max(r, 78.0)

                # Ultra-fast scanner cut-off: for dense multi-port probing,
                # escalate immediately so the source is dropped persistently.
                if (not is_infra_ip) and rapid_scan_ioc:
                    action = "CRITICAL_BLOCK"
                    r = max(r, 92.0)

                # Deception pivot for high-confidence attackers.
                # This is intentionally strict so benign traffic is never redirected.
                deception_candidate = (
                    (strong_scan_ioc and unique_ports >= 10 and incomplete_handshakes >= 6)
                    or strong_payload_ioc
                )
                if deception_candidate and (persistence >= 1 or rapid_scan_ioc) and action in {"BLOCK", "CRITICAL_BLOCK"}:
                    action = "DECEIVE"
                    r = max(r, 91.0)

                scan_persistent = (
                    (strong_scan_ioc or rapid_scan_ioc) and (
                        incomplete_handshakes >= 8
                        or unique_ports >= 16
                        or persistence >= 2
                    )
                )
                
                # Confidence Filtering (V16.1)
                # If risk is borderline but payload is suspicious, elevate to Suspicious
                if (not is_infra_ip) and r < 40 and payload_prob > 0.5:
                    r = 45.0
                    action = "RATE_LIMIT"

                # --- V16.6: Consensus-Based Benign Collector ---
                # Stability Check: Only learn from IPs that are consistently benign
                if r < 15 and anomaly < 0.4 and payload_prob < 0.2:
                    ip_stability[ip] += 1
                    
                    # Consensus Gate: Require 5 consecutive stable cycles
                    if ip_stability[ip] >= 5:
                        # Append to environment-specific baseline
                        new_baseline_row = group.iloc[0:1].copy()
                        # Ensure we only save relevant features to avoid bloat
                        if not os.path.exists(BASELINE_PATH):
                            new_baseline_row.to_csv(BASELINE_PATH, index=False)
                        else:
                            new_baseline_row.to_csv(BASELINE_PATH, mode='a', header=False, index=False)
                        
                        # Reset counter to avoid duplicate logging of same "stream"
                        ip_stability[ip] = 0 
                else:
                    # Reset stability if ANY signal spikes
                    ip_stability[ip] = 0

                block_res = "LOGGED"
                if action == "CRITICAL_BLOCK":
                    block_res_dict = defender.block_ip(ip, persistent=True)
                    block_res = block_res_dict.get("status", "error")
                elif action == "BLOCK":
                    block_res_dict = defender.block_ip(ip, persistent=scan_persistent)
                    block_res = block_res_dict.get("status", "error")
                elif action == "DECEIVE":
                    deceptive_res = defender.redirect_to_honeypot(ip)
                    block_res = deceptive_res.get("status", "error")
                    if block_res in {"success", "dry-run"}:
                        # Preserve true source attribution even when honeypot runs locally.
                        append_alert({
                            "type": "honeypot_hit",
                            "time": time.time(),
                            "src_ip": ip,
                            "path": "/deception-redirect",
                            "method": "REDIRECT",
                            "source": "orchestrator"
                        })
                elif action == "RATE_LIMIT":
                    limit_res = defender.throttle_ip(ip, rate_kbps=100)
                    block_res = limit_res.get("status", "error")
                
                geo = get_ip_geo(ip)
                
                if not defender.is_protected(ip) and (action != "LOG" or r >= 30.0):
                    now_ts = time.time()
                    prev = last_alert_state.get(ip)
                    cooldown = alert_cooldowns.get(action, 20)
                    should_emit = True

                    if prev:
                        same_action = prev.get("action") == action
                        risk_delta = abs(float(prev.get("risk", 0.0)) - float(r))
                        enough_time = (now_ts - float(prev.get("ts", 0.0))) >= cooldown
                        should_emit = (not same_action) or (risk_delta >= 5.0) or enough_time

                    if should_emit:
                        alert = {
                            'time': now_ts, 'src_ip': ip, 'risk': r,
                            'anomaly': anomaly, 'raw_anomaly': float(group['raw_anomaly'].mean()),
                            'payload_score': payload_prob,
                            'persistence': persistence, 'breakdown': assessment["breakdown"],
                            'action': action, 'status': block_res, 'meta': meta,
                            'lat': geo['lat'] if geo else None, 'lon': geo['lon'] if geo else None
                        }
                        append_alert(alert)
                        log_to_siem(alert)
                        last_alert_state[ip] = {"action": action, "risk": float(r), "ts": now_ts}
            
            print(f"--- SOC CYCLE COMPLETE: {pcap} ---\n", flush=True)
        except Exception as e:
            print(f"Cycle Error: {e}")
            time.sleep(5)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', '--interface', default='en0', help='Network interface to sniff')
    parser.add_argument('--duration', type=int, default=3, help='Cycle duration in seconds')
    parser.add_argument('--model', default='models/ensemble_model.joblib', help='Path to ensemble model')
    parser.add_argument('--dashboard-url', help='Webhook URL for dashboard events')
    parser.add_argument('--honeypot-ip', default='127.0.0.1', help='Honeypot target IP for DECEIVE action')
    parser.add_argument('--honeypot-port', type=int, default=8080, help='Honeypot target port for DECEIVE action')
    parser.add_argument('--no-dry-run', dest='dry', action='store_false', help='Enable active blocking')
    args = parser.parse_args()
    
    if args.dashboard_url:
        GLOBAL_DASHBOARD_URL = args.dashboard_url
        
    run_cycle(
        args.iface,
        args.duration,
        args.model,
        dry_run=args.dry,
        honeypot_ip=args.honeypot_ip,
        honeypot_port=args.honeypot_port,
    )
