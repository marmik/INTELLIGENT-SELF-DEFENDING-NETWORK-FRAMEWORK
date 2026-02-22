import time
import json
import threading
from collections import defaultdict
from pathlib import Path
from tshark_wrapper import capture_to_pcap
from packet_to_flow import pcap_to_flows
from ml.model import IsolationModel
from risk import risk_score
from defender import Defender
import socket
import struct
import urllib.request

ALERTS_FILE = Path('alerts.json')

def get_interface_ip(iface: str) -> str:
    # Simplified helper to get interface IP
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        iface_bytes = iface[:15].encode('utf-8')
        packed_iface = struct.pack('256s', iface_bytes)
        info = fcntl.ioctl(s.fileno(), 0x8915, packed_iface)
        return socket.inet_ntoa(info[20:24])
    except Exception:
        return "192.168.1.1"

def is_spoofed(ip: str, iface_ip: str) -> bool:
    # Basic spoofing check
    iface_parts = iface_ip.split(".")
    ip_parts = ip.split(".")
    if len(iface_parts) < 2 or len(ip_parts) < 2:
        return False
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

def run_cycle(interface: str = 'en0', duration: int = 10, model_path: str = 'models/isolation_model.joblib', dry_run=True):
    iface_ip = get_interface_ip(interface)
    defender = Defender(dry_run=dry_run)
    
    # Start flush thread
    threading.Thread(target=flush_loop, args=(defender,), daemon=True).start()

    # Intelligence Layer: Persistent Threat Memory
    threat_memory = defaultdict(int)

    print(f"ISDNF Autonomous SOC Active on {interface} ({iface_ip})")
    
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

            model = IsolationModel()
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
                
                # Multi-Dimensional Risk Scoring
                assessment = risk_score(anomaly, pkt, b, persistence=persistence)
                
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
                
                alert = {
                    'time': time.time(),
                    'src_ip': ip,
                    'risk': r,
                    'anomaly': anomaly,
                    'persistence': persistence,
                    'spoofed': is_spoof,
                    'breakdown': assessment["breakdown"],
                    'action': action,
                    'status': block_res
                }
                append_alert(alert)
        except Exception as e:
            print(f"Cycle Error: {e}")
            time.sleep(5)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', default='en0')
    parser.add_argument('--duration', type=int, default=10)
    parser.add_argument('--model', default='models/isolation_model.joblib')
    parser.add_argument('--no-dry-run', dest='dry', action='store_false')
    args = parser.parse_args()
    run_cycle(args.iface, args.duration, args.model, dry_run=args.dry)
