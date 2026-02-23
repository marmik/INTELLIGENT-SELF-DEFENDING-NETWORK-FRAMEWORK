import pandas as pd
import numpy as np
import random
import time
from pathlib import Path

def generate_v12_data(n_samples=8000, out_file='src/data/v12_training_flows.csv'):
    rows = []
    
    # Categories: 
    # 0 = Normal Browsing
    # 1 = CDN/Cloud (Trusted but high volume)
    # 2 = Nmap Scan
    # 3 = Slowloris (Low/Slow)
    # 4 = Volumetric (DDoS)
    
    for _ in range(n_samples):
        cat = random.choices([0, 1, 2, 3, 4], weights=[0.6, 0.15, 0.1, 0.05, 0.1])[0]
        
        # Default Features
        pkt_count = random.randint(5, 50)
        byte_count = pkt_count * random.randint(100, 1500)
        duration = random.uniform(0.1, 10.0)
        sc, ac, fc, rc = random.randint(1, 5), random.randint(1, 5), 0, 0
        uniq_ports = 1
        iat_mean = duration / pkt_count
        iat_std = iat_mean * 0.5
        payload_ratio = random.uniform(0.2, 0.8)
        
        if cat == 1: # CDN/Cloud Profiles (Bursty but legitimate)
            pkt_count = random.randint(100, 1000)
            byte_count = pkt_count * random.randint(1200, 1500)
            duration = random.uniform(0.5, 2.0)
            payload_ratio = 0.9
            iat_std = iat_mean * 1.2 # Jittery
            
        elif cat == 2: # Nmap Recon
            pkt_count = random.randint(1, 3)
            byte_count = pkt_count * 44
            duration = random.uniform(0.001, 0.1)
            sc, ac = 1, 0
            rc = random.choice([0, 1])
            uniq_ports = 20.0
            payload_ratio = 1.0 # Headers only
            
        elif cat == 3: # Slowloris (Long duration, low throughput)
            pkt_count = random.randint(3, 10)
            duration = random.uniform(30.0, 60.0)
            byte_count = pkt_count * 60
            iat_mean = duration / pkt_count
            iat_std = 0.1
            payload_ratio = 1.0 # Mostly control packets
            
        elif cat == 4: # Volumetric
            pkt_count = random.randint(5000, 20000)
            duration = random.uniform(1.0, 5.0)
            byte_count = pkt_count * random.randint(64, 128)
            sc = pkt_count
            ac = 0
            payload_ratio = 1.0
            
        pps = pkt_count / max(0.1, duration)
        bps = byte_count / max(0.1, duration)
        
        rows.append({
            'mac_ip_mismatch': 0, 'multiple_ips_per_mac': 1,
            'ttl_mean': random.choice([64, 128]), 'ttl_var': random.uniform(0, 1),
            'abnormal_ttl_count': 0, 'fragmentation_rate': 0,
            'syn_count': sc, 'ack_count': ac, 'fin_count': fc, 'rst_count': rc,
            'incomplete_handshakes': 1 if sc > 0 and ac == 0 else 0,
            'rst_syn_ratio': rc/sc if sc > 0 else 0,
            'avg_tcp_window': 64240, 'udp_burst_rate': 0, 'udp_flood_indicator': 0,
            'icmp_flood_rate': 0, 'echo_req_res_ratio': 0, 'payload_entropy': 0,
            'header_payload_ratio': payload_ratio, 'iat_mean': iat_mean,
            'iat_min': iat_mean * 0.1, 'iat_max': iat_mean * 2, 'iat_std': iat_std,
            'pps': pps, 'bps': bps, 'burst_detection': 1 if pps > 1000 else 0,
            'flow_duration': duration, 'total_packets': pkt_count, 'total_bytes': byte_count,
            'avg_packet_size': byte_count / pkt_count, 'min_packet_size': 40, 'max_packet_size': 1500,
            'fwd_bwd_packet_ratio': 1.0, 'one_sided_flow': 1 if ac == 0 else 0,
            'unique_ports_per_sec': uniq_ports, 'connection_attempt_rate': sc / max(0.1, duration),
            'beaconing_score': 1 if iat_std < 0.01 else 0, 'out_in_byte_ratio': 1.0,
            'pct_incomplete_handshakes': (1 if sc > 0 and ac == 0 else 0),
            'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'protocol': 'TCP'
        })
        
    df = pd.DataFrame(rows)
    Path(out_file).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_file, index=False)
    print(f"Generated {n_samples} flows in {out_file}")

if __name__ == "__main__":
    generate_v12_data()
