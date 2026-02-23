import requests
import time
import random

def run_stress_test(n=500, delay=0.01):
    url = "http://127.0.0.1:5010/events"
    print(f"--- Starting SOC V12.0 Pressure Test ({n} events) ---")
    
    ips = [f"192.168.1.{random.randint(2, 254)}" for _ in range(20)]
    
    for i in range(n):
        ip = random.choice(ips)
        risk = random.randint(1, 95)
        action = "LOG"
        if risk >= 80: action = "BLOCK"
        elif risk >= 45: action = "RATE_LIMIT"
        
        payload = {
            "time": time.time(),
            "src_ip": ip,
            "risk": float(risk),
            "anomaly": risk / 100.0,
            "intensity": 0.5,
            "persistence": 0,
            "metadata": {"dst_ports": [80, 443]},
            "spoof_detected": False,
            "action": action
        }
        
        try:
            requests.post(url, json=payload, timeout=0.1)
        except:
            pass
            
        if i % 50 == 0:
            print(f"  Pushed {i} events...")
            
    print("--- Pressure Test Complete ---")

if __name__ == "__main__":
    run_stress_test()
