"""Simulated orchestrator runner that processes an existing flows CSV instead of
capturing. Updated to use the High-Performance CIC-IDS-2017 Engine.
Enhanced with telemetry pulses and host exclusion logic."""
import time
import json
import socket
from pathlib import Path
import pandas as pd
import requests
from ml.high_perf_model import HighPerfInferenceEngine
from defender import Defender
from risk import risk_score
import urllib.request

ALERTS_FILE = Path('alerts.json')

def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def append_alert(alert: dict):
    arr = []
    if ALERTS_FILE.exists():
        try:
            arr = json.loads(ALERTS_FILE.read_text())
        except Exception:
            arr = []
    arr.append(alert)
    ALERTS_FILE.write_text(json.dumps(arr, indent=2))

def run_sim(flows_csv: str, dry_run=True, dashboard_url: str = None):
    print(f"--- ISDNF High-Performance Simulation Engine ---")
    print(f"Input: {flows_csv}")
    
    # Initialize the new optimized engine
    model = HighPerfInferenceEngine()
    host_ip = get_host_ip()
    print(f"Detected Host IP: {host_ip} (Excluding from auto-block)")
    
    df = pd.read_csv(flows_csv)
    # Clean column names (training sets have leading spaces)
    df.columns = df.columns.str.strip()
    
    if df.empty:
        print('No flows in CSV.')
        return
        
    # Inject dummy payload features if missing (V16.0 Compatibility)
    payload_cols = ['payload_entropy', 'uri_length', 'suspicious_keywords_count', 'is_encoded_payload']
    for col in payload_cols:
        if col not in df.columns:
            print(f"Injecting dummy {col} for simulation...")
            df[col] = 0.0 if 'count' not in col else 0
        
    defender = Defender(dry_run=dry_run)
    
    # Run Inference (V16.0 Triple Return)
    flow_anomalies, labels, payload_probs = model.predict(df)
    df['anomaly'] = flow_anomalies
    df['classification'] = labels
    df['payload_score'] = payload_probs
    
    print(f"Processed {len(df)} flows. Analyzing hybrid detections...")
    
    global_total = 0
    detections = 0
    
    for idx, row in df.iterrows():
        global_total += 1
        anomaly = float(row['anomaly'])
        payload_prob = float(row['payload_score'])
        label = row['classification']
        
        # Fallback for missing IP columns in training datasets
        ip = row.get('src_ip', f"10.0.0.{100 + (idx % 50)}")
        
        # Multi-dimensional risk assessment (Hybrid V16.0)
        assessment = risk_score(anomaly, 10, 1024, persistence=0, 
                                payload_score=payload_prob, 
                                metadata={'model_classification': label})
        
        action = assessment['action']
        final_risk = assessment['score']

        if action != 'LOG' or final_risk >= 30.0:
            detections += 1
            print(f"[!] {label} detected (FlowAnom: {anomaly:.2f}, PayloadProb: {payload_prob:.2f}) -> Risk: {final_risk:.1f}% [{action}]")
            
            # Host Exclusion Logic
            if ip == host_ip:
                print(f"[-] Suppression: IP {ip} is local host. Skipping block.")
                action = "LOG (LOCAL)"
                res = {"status": "skipped"}
            else:
                if action == "CRITICAL_BLOCK":
                    res = defender.block_ip(ip, persistent=True)
                elif action == "BLOCK":
                    res = defender.block_ip(ip)
                elif action == "RATE_LIMIT":
                    res = defender.throttle_ip(ip)
                else:
                    res = {"status": "logged"}
            
            status_str = res.get('status', 'success')
            
            alert = {
                'time': time.time(),
                'src_ip': ip,
                'risk': final_risk,
                'anomaly': anomaly,
                'payload_score': payload_prob,
                'label': label,
                'meta': {
                    'model_classification': label,
                    'is_local': (ip == host_ip)
                },
                'action': action,
                'status': status_str,
                'source': 'simulation'
            }
            append_alert(alert)
            
            if dashboard_url:
                try:
                    req = urllib.request.Request(dashboard_url.rstrip('/') + '/events', 
                                              data=json.dumps(alert).encode(),
                                              headers={'Content-Type': 'application/json'},
                                              method='POST')
                    urllib.request.urlopen(req, timeout=1)
                except: pass
        
        # Slow down slightly to allow dashboard to animate
        time.sleep(0.05)
                    
    print(f"Simulation Complete. Total Flows Processed: {global_total}")
    print(f"Total Detections: {detections}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--flows', required=True)
    parser.add_argument('--no-dry-run', dest='dry', action='store_false', default=True)
    parser.add_argument('--dashboard', dest='dashboard', default=None, help='dashboard base URL to POST events to')
    args = parser.parse_args()
    
    run_sim(args.flows, dry_run=args.dry, dashboard_url=args.dashboard)
