import subprocess
import pandas as pd
import numpy as np
import math
from collections import defaultdict
import os

# Full CIC-IDS-2017 Feature Set + Hybrid Payload Features
FEATURE_LIST = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
    'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
    'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
    'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

HYBRID_FEATURES = [
    'payload_entropy', 'uri_length', 'suspicious_keywords_count', 
    'http_method_encoded', 'is_encoded_payload', 'payload_len'
]

def calculate_entropy(data_hex):
    if not data_hex: return 0.0
    try:
        data = bytes.fromhex(data_hex.replace(':', ''))
        if not data: return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
    except: return 0.0

def pcap_to_flows(pcap_path, out_csv):
    """
    Directional flow extraction with hybrid payload feature augmentation.
    """
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst", "ip.proto", "tcp.srcport", "tcp.dstport",
        "udp.srcport", "udp.dstport", "frame.len", "ip.ttl", "tcp.flags", "tcp.window_size", "eth.src",
        "http.request.uri", "http.request.method", "dns.qry.name", "tls.handshake.extensions_server_name", "data.data"
    ]
    
    cmd = ["tshark", "-r", pcap_path, "-T", "fields"]
    for f in fields: cmd.extend(["-e", f])
    
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lines = proc.stdout.strip().split('\n')
    except Exception as e:
        print(f"Extraction Error: {e}")
        pd.DataFrame(columns=FEATURE_LIST + HYBRID_FEATURES + ["src_ip", "dst_ip", "src_port", "dst_port", "packet_count", "byte_count", "src_mac", "ttl_mean"]).to_csv(out_csv, index=False)
        return out_csv

    if not lines or (len(lines) == 1 and not lines[0]):
        pd.DataFrame(columns=FEATURE_LIST + HYBRID_FEATURES + ["src_ip", "dst_ip", "src_port", "dst_port", "packet_count", "byte_count", "src_mac", "ttl_mean"]).to_csv(out_csv, index=False)
        return out_csv

    flows = {}
    suspicious_keywords = ["union", "select", "insert", "delete", "drop", "script", "alert", "eval", "base64", "cmd"]

    for line in lines:
        parts = line.split('\t')
        if len(parts) < 11: continue
        
        try:
            if not parts[1] or not parts[2]: continue
            
            ts = float(parts[0])
            src, dst, proto = parts[1], parts[2], parts[3]
            sport = parts[4] or parts[6] or "0"
            dport = parts[5] or parts[7] or "0"
            length = int(parts[8])
            ttl = int(parts[9]) if parts[9] else 64
            flags = int(parts[10], 16) if parts[10] else 0
            win = int(parts[11]) if parts[11] else 0
            mac = parts[12] if len(parts) > 12 else "00:00:00:00:00:00"
            
            # Payload Metadata (Fields 13-17)
            uri = parts[13] if len(parts) > 13 else ""
            method = parts[14] if len(parts) > 14 else ""
            dns_query = parts[15] if len(parts) > 15 else ""
            sni = parts[16] if len(parts) > 16 else ""
            payload_hex = parts[17] if len(parts) > 17 else ""
            
            key = f"{src}_{dst}_{proto}_{sport}_{dport}"
            if key not in flows:
                flows[key] = {
                    "pkts": [], "src": src, "dst": dst, "proto": proto, 
                    "sport": int(sport), "dport": int(dport), "mac": mac,
                    "payload_data": []
                }
            
            f = flows[key]
            f["pkts"].append({"ts": ts, "len": length, "flags": flags, "win": win, "ttl": ttl})
            if any([uri, method, dns_query, sni, payload_hex]):
                f["payload_data"].append({
                    "uri": uri, "method": method, "dns": dns_query, "sni": sni, "hex": payload_hex
                })
        except: continue

    rows = []
    for key, data in flows.items():
        if not data["pkts"]: continue
        
        pkts = sorted(data["pkts"], key=lambda x: x["ts"])
        dur = pkts[-1]["ts"] - pkts[0]["ts"]
        dur_us = int(dur * 1e6)
        dur_safe = dur if dur > 0 else 1.0
        all_lens = [p["len"] for p in pkts]
        
        # --- Payload Feature Engineering ---
        payload_entropy = 0.0
        uri_len = 0
        kw_count = 0
        method_enc = 0 # 0=None, 1=GET, 2=POST, 3=Other
        is_encoded = 0
        total_payload_len = 0
        
        if data["payload_data"]:
            combined_payload = ""
            for p in data["payload_data"]:
                combined_payload += (p["uri"] + p["method"] + p["dns"] + p["sni"] + p["hex"]).lower()
                uri_len = max(uri_len, len(p["uri"]))
                if p["method"] == "GET": method_enc = max(method_enc, 1)
                elif p["method"] == "POST": method_enc = max(method_enc, 2)
                elif p["method"]: method_enc = max(method_enc, 3)
                
                if p["hex"]:
                    total_payload_len += len(p["hex"]) // 2
                    payload_entropy = max(payload_entropy, calculate_entropy(p["hex"]))
            
            kw_count = sum(1 for kw in suspicious_keywords if kw in combined_payload)
            if "%" in combined_payload or "+" in combined_payload: is_encoded = 1

        base_row = {f: 0 for f in FEATURE_LIST}
        # Port Normalization: Default to 80 if 0 or missing to prevent diversity inflation
        dport_final = int(dport) if dport and dport != "0" else 80
        sport_final = int(sport) if sport and sport != "0" else 443
        
        base_row.update({
            "Destination Port": dport_final, "Flow Duration": dur_us,
            "Total Fwd Packets": len(pkts), "Total Backward Packets": 0,
            "Total Length of Fwd Packets": sum(all_lens), "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Max": max(all_lens), "Fwd Packet Length Min": min(all_lens),
            "Fwd Packet Length Mean": np.mean(all_lens), "Flow Bytes/s": sum(all_lens) / dur_safe,
            "Flow Packets/s": len(pkts) / dur_safe,
            "FIN Flag Count": sum(1 for p in pkts if p["flags"] & 0x01),
            "SYN Flag Count": sum(1 for p in pkts if p["flags"] & 0x02),
            "RST Flag Count": sum(1 for p in pkts if p["flags"] & 0x04),
            "PSH Flag Count": sum(1 for p in pkts if p["flags"] & 0x08),
            "ACK Flag Count": sum(1 for p in pkts if p["flags"] & 0x10),
            "URG Flag Count": sum(1 for p in pkts if p["flags"] & 0x20),
            "Init_Win_bytes_forward": pkts[0]["win"] if pkts else 0,
        })
        
        # Hybrid Features
        base_row.update({
            "payload_entropy": payload_entropy, "uri_length": uri_len,
            "suspicious_keywords_count": kw_count, "http_method_encoded": method_enc,
            "is_encoded_payload": is_encoded, "payload_len": total_payload_len
        })
        
        base_row.update({
            "src_ip": data["src"], "dst_ip": data["dst"], "src_port": data["sport"],
            "dst_port": data["dport"], "packet_count": len(pkts), "byte_count": sum(all_lens),
            "src_mac": data["mac"], "ttl_mean": np.mean([p["ttl"] for p in pkts])
        })
        rows.append(base_row)

    df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=FEATURE_LIST + HYBRID_FEATURES + ["src_ip", "dst_ip", "packet_count"])
    df.to_csv(out_csv, index=False)
    return out_csv
