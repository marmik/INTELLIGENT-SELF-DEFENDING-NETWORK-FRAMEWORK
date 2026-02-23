import pandas as pd
import numpy as np
import random
import time
from pathlib import Path

def generate_v11_data(n_samples=5000, out_file='src/data/v11_training_flows.csv'):
    rows = []
    
    # Categories: 0=Normal, 1=Scan(Nmap-style), 2=Volumetric/DDoS, 3=Beaconing/C2
    for _ in range(n_samples):
        cat = random.choices([0, 1, 2, 3], weights=[0.7, 0.15, 0.1, 0.05])[0]
        
        # Base metadata
        pkt_count = random.randint(1, 20)
        byte_count = pkt_count * random.randint(40, 1500)
        duration = random.uniform(0.001, 10.0)
        
        # 1. Layer 2 
        mac_ip_mismatch = 0
        multiple_ips_per_mac = 1
        
        # 2. Layer 3
        ttl_mean = 64 if random.random() > 0.1 else 128
        ttl_var = random.uniform(0, 2)
        abnorm_ttl = 0
        frag_rate = 0
        
        # 3. Layer 4 TCP
        sc, ac, fc, rc = 0, 0, 0, 0
        avg_win = 64240
        
        # 4. Timing
        iat_mean = duration / max(1, pkt_count)
        iat_std = iat_mean * 0.5
        pps = pkt_count / max(0.1, duration)
        bps = byte_count / max(0.1, duration)
        
        # 10. Behavioral
        uniq_ports_sec = 0.1
        conn_att_rate = 0
        beacon_score = 0
        
        if cat == 0: # NORMAL
            sc = random.randint(1, 5)
            ac = sc + random.randint(0, 5)
            payload_ratio = random.uniform(0.1, 0.8)
            iat_std = iat_mean * 0.8
            
        elif cat == 1: # SCAN (Nmap-style SYN scan)
            pkt_count = random.randint(1, 3) # Very few packets per flow
            byte_count = pkt_count * 44 # Just headers
            sc = 1
            ac = 0 # Incomplete handshake
            rc = random.choice([0, 1]) # Maybe a RST back
            duration = random.uniform(0.001, 0.05)
            payload_ratio = 1.0 # Pure headers
            conn_att_rate = 1.0 / max(0.01, duration)
            uniq_ports_sec = 10.0
            
        elif cat == 2: # VOLUMETRIC
            pkt_count = random.randint(500, 5000)
            byte_count = pkt_count * random.randint(1000, 1500)
            duration = random.uniform(0.5, 3.0)
            sc = pkt_count // 2
            ac = sc
            pps = pkt_count / duration
            bps = byte_count / duration
            payload_ratio = 0.5
            
        elif cat == 3: # BEACON
            pkt_count = 15
            duration = 15.0
            iat_mean = 1.0
            iat_std = 0.01 # Very periodic
            beacon_score = 1.0
            payload_ratio = 0.1
            
        # Composite features
        inc_hs = 1 if sc > 0 and ac == 0 else 0
        rst_syn_ratio = rc / sc if sc > 0 else 0
        hdr_pay_ratio = payload_ratio
        pct_inc_hs = inc_hs / max(1, pkt_count)
        
        rows.append({
            'mac_ip_mismatch': mac_ip_mismatch,
            'multiple_ips_per_mac': multiple_ips_per_mac,
            'ttl_mean': ttl_mean,
            'ttl_var': ttl_var,
            'abnormal_ttl_count': abnorm_ttl,
            'fragmentation_rate': frag_rate,
            'syn_count': sc,
            'ack_count': ac,
            'fin_count': fc,
            'rst_count': rc,
            'incomplete_handshakes': inc_hs,
            'rst_syn_ratio': rst_syn_ratio,
            'avg_tcp_window': avg_win,
            'udp_burst_rate': 0,
            'udp_flood_indicator': 0,
            'icmp_flood_rate': 0,
            'echo_req_res_ratio': 0,
            'payload_entropy': 0,
            'header_payload_ratio': hdr_pay_ratio,
            'iat_mean': iat_mean,
            'iat_min': iat_mean * 0.5,
            'iat_max': iat_mean * 1.5,
            'iat_std': iat_std,
            'pps': pps,
            'bps': bps,
            'burst_detection': 1 if pps > 1000 else 0,
            'flow_duration': duration,
            'total_packets': pkt_count,
            'total_bytes': byte_count,
            'avg_packet_size': byte_count / pkt_count,
            'min_packet_size': 40,
            'max_packet_size': 1500,
            'fwd_bwd_packet_ratio': 1.0,
            'one_sided_flow': 1 if ac == 0 else 0,
            'unique_ports_per_sec': uniq_ports_sec,
            'connection_attempt_rate': conn_att_rate,
            'beaconing_score': beacon_score,
            'out_in_byte_ratio': 1.0,
            'pct_incomplete_handshakes': pct_inc_hs,
            # Extra columns required by model training but not features 
            'src_ip': '1.1.1.1',
            'dst_ip': '2.2.2.2',
            'protocol': 'TCP',
            'packet_count': pkt_count, # duplicate for prepare() if needed
            'byte_count': byte_count,
            'dst_port': 80
        })
        
    df = pd.DataFrame(rows)
    Path(out_file).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_file, index=False)
    print(f"Generated {n_samples} flows in {out_file}")

if __name__ == "__main__":
    generate_v11_data()
