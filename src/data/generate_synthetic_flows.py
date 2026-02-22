import argparse
import random
import pandas as pd
from pathlib import Path
import time


def random_ip():
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def generate(n=1000, anomaly_frac=0.02):
    rows = []
    now = time.time()
    for i in range(n):
        src = random_ip()
        dst = random_ip()
        proto = random.choice(['TCP','UDP','ICMP'])
        sport = random.randint(1024,65535) if proto in ('TCP','UDP') else None
        dport = random.choice([80,443,53,22,123, None]) if proto in ('TCP','UDP') else None
        # normal traffic
        if random.random() < anomaly_frac:
            packet_count = random.randint(500, 5000)
            byte_count = packet_count * random.randint(200,1500)
            duration = random.uniform(0.1, 60.0)
        else:
            packet_count = random.randint(1, 200)
            byte_count = packet_count * random.randint(40,1200)
            duration = random.uniform(0.01, 10.0)

        start = now - random.uniform(0, 3600)
        end = start + duration
        rows.append({
            'src_ip': src,
            'dst_ip': dst,
            'protocol': proto,
            'src_port': sport,
            'dst_port': dport,
            'packet_count': packet_count,
            'byte_count': byte_count,
            'start_time': start,
            'end_time': end,
            'duration': duration,
        })
    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    parser.add_argument('--n', type=int, default=1000)
    args = parser.parse_args()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    df = generate(n=args.n)
    df.to_csv(args.out, index=False)
    print('Wrote', args.out)


if __name__ == '__main__':
    main()
