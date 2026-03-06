import pandas as pd
import joblib
import os
import time
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))
from ml.finetune import finetune

def staged_adaptation_loop(baseline_path="models/benign_baseline.csv", check_interval=300):
    """V16.6: Staged Adaptation Service.
    Tiered updates to ensure stability and prevent poisoning.
    """
    print("--- ISDNF ADAPTIVE LEARNER SERVICE ACTIVE ---")
    last_processed_count = 0
    
    while True:
        try:
            if os.path.exists(baseline_path):
                df = pd.read_csv(baseline_path)
                current_count = len(df)
                
                # Check for new data threshold (e.g., every 500 new stable points)
                if current_count >= last_processed_count + 500:
                    print(f"Adaptive Learning: Threshold reached ({current_count} flows). Starting Tier 2 update...")
                    
                    # Tier 2: Partial refit of IsolationForest (Behaviors)
                    # We use the existing finetune script but target the baseline
                    finetune(baseline_path)
                    
                    # Snapshot/Versioning
                    snapshot_path = f"models/backup/cic_model_{int(time.time())}.pt"
                    os.makedirs("models/backup", exist_ok=True)
                    if os.path.exists("models/cic_model_v1.pt"):
                        import shutil
                        shutil.copy("models/cic_model_v1.pt", snapshot_path)
                        print(f"Snapshot created: {snapshot_path}")
                    
                    last_processed_count = current_count
                
            time.sleep(check_interval)
        except Exception as e:
            print(f"Adaptive Learner Error: {e}")
            time.sleep(60)

if __name__ == "__main__":
    staged_adaptation_loop()
