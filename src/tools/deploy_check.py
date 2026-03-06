import os
from pathlib import Path

def check_deployment():
    required_paths = [
        'models/cic_model_v1.pt',
        'models/payload_model.joblib',
        'models/payload_vectorizer.joblib',
        'src/orchestrator.py',
        'src/dashboard/app.py',
        'captures',
        'alerts.json'
    ]
    
    print("--- ISDNF DEPLOYMENT READINESS CHECK ---")
    all_ok = True
    for p in required_paths:
        path = Path(p)
        status = "[ OK ]" if path.exists() else "[FAIL]"
        if not path.exists(): all_ok = False
        print(f"{status} {p}")
        
    if all_ok:
        print("\nSYSTEM READY FOR PRODUCTION LAUNCH.")
    else:
        print("\nDEPLOYMENT BLOCKED: MISSING COMPONENTS.")
    
if __name__ == "__main__":
    check_deployment()
