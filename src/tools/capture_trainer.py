import subprocess
import time
import sys
import os
import pandas as pd
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))
from packet_to_flow import pcap_to_flows

def capture_for_training(target_ip, duration=30, label="ATTACK"):
    """
    Captures traffic from a target IP (e.g. Kali) and prepares it for training.
    """
    print(f"--- TRAINING CAPTURE START: Targeting {target_ip} for {duration}s ---")
    pcap = f"training_captures/attack_{int(time.time())}.pcap"
    os.makedirs("training_captures", exist_ok=True)
    
    # Capture only traffic from target_ip
    cmd = ["sudo", "tshark", "-i", "any", "-f", f"host {target_ip}", "-a", f"duration:{duration}", "-w", pcap]
    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd)
    
    if not os.path.exists(pcap):
        print("Capture failed.")
        return
        
    csv = pcap.replace(".pcap", ".csv")
    print(f"Extracting flows to {csv}...")
    pcap_to_flows(pcap, csv)
    
    # Label the data
    df = pd.read_csv(csv)
    df['label'] = label
    df.to_csv(csv, index=False)
    
    print(f"--- SUCCESS: {len(df)} flows captured and labeled as {label} ---")
    print(f"Data saved to: {csv}")
    print("Append this to your master dataset to retrain.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 capture_trainer.py <IP> [duration] [label]")
        sys.exit(1)
        
    ip = sys.argv[1]
    dur = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    lbl = sys.argv[3] if len(sys.argv) > 3 else "ATTACK"
    
    capture_for_training(ip, dur, lbl)
