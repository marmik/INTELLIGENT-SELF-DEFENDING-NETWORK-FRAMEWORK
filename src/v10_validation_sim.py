import time
import json
import pandas as pd
from pathlib import Path
from ml.model import EnsembleModel
from risk import risk_score
from orchestrator import is_spoofed

ALERTS_FILE = Path('alerts.json')

def append_alert(alert: dict):
    arr = []
    if ALERTS_FILE.exists():
        try:
            arr = json.loads(ALERTS_FILE.read_text())
        except Exception:
            arr = []
    arr.append(alert)
    ALERTS_FILE.write_text(json.dumps(arr, indent=2))

def run_test_cases():
    print("--- ISDNF V10.0 Validation Simulator ---")
    model = EnsembleModel()
    model.load('models/ensemble_model.joblib')
    
    # Mock Interface IP
    iface_ip = "192.168.1.33"
    dashboard_url = "http://127.0.0.1:5010/events"
    
    test_cases = [
        {
            "id": "TC1: Public Datacenter Traffic (Google DNS)",
            "src_ip": "8.8.8.8",
            "dst_ports": [53],
            "packet_count": 500,
            "byte_count": 100000,
            "anomaly_force": 0.7, # High anomaly but trusted service
            "expected_spoof": False
        },
        {
            "id": "TC2: Private IP Spoof (Non-Local 10.x)",
            "src_ip": "10.0.0.99",
            "dst_ports": [445, 139],
            "packet_count": 50,
            "byte_count": 5000,
            "anomaly_force": 0.8,
            "expected_spoof": True
        },
        {
            "id": "TC3: Stealth Nmap SYN-Scan (V11.0 Test)",
            "src_ip": "192.168.1.105",
            "dst_ports": list(range(1000, 1101)), # Scanning 100 non-standard ports
            "packet_count": 100, # 1 packet per port
            "byte_count": 4400, # Only headers
            "anomaly_force": 0.45, # Moderate initial anomaly
            "expected_spoof": False
        }
    ]
    
    for tc in test_cases:
        print(f"\nProcessing {tc['id']}...")
        
        # 1. Spoofing Check
        spoofed = is_spoofed(tc['src_ip'], iface_ip)
        print(f"  Spoofed Detected: {spoofed} (Expected: {tc['expected_spoof']})")
        
        # 2. Risk Evaluation
        meta = {
            "dst_ports": tc['dst_ports'],
            "is_standard_service": any(p in [443, 80, 53, 8080] for p in tc['dst_ports']),
            "is_local_infrastructure": False
        }
        
        # We simulate the risk score assuming the model consensus is tc['anomaly_force']
        r_data = risk_score(tc['anomaly_force'], tc['packet_count'], tc['byte_count'], metadata=meta)
        risk = r_data['score']
        intensity = r_data['breakdown']['intensity']
        
        print(f"  Risk Score: {risk}% (Anomaly: {tc['anomaly_force']})")
        
        # 3. Alert Generation
        alert = {
            'time': int(time.time()),
            'src_ip': tc['src_ip'],
            'risk': risk,
            'anomaly': tc['anomaly_force'],
            'intensity': intensity,
            'persistence': 0,
            'metadata': meta,
            'spoof_detected': spoofed,
            'action': r_data['action']
        }
        
        append_alert(alert)
        
        # Post to dashboard
        try:
            import requests
            requests.post(dashboard_url, json=alert, timeout=3)
            print(f"  Pushed to Dashboard: OK")
        except Exception as e:
            print(f"  Pushed to Dashboard: FAILED ({e})")

if __name__ == "__main__":
    run_test_cases()
