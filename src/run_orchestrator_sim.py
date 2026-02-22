"""Simulated orchestrator runner that processes an existing flows CSV instead of
capturing."""
import time
import json
from pathlib import Path
from .ml.model import IsolationModel
from .risk import risk_score
from .defender import Defender
import pandas as pd

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


def run_sim(flows_csv: str, model_path: str = 'models/isolation_model.joblib', dry_run=True, dashboard_url: str = None):
    model = IsolationModel()
    model.load(model_path)
    df = pd.read_csv(flows_csv)
    if df.empty:
        print('No flows')
        return
    scores = model.score(df)
    df['anomaly'] = scores
    defender = Defender(dry_run=dry_run)

    for idx, row in df.iterrows():
        anomaly = float(row['anomaly'])
        pkt = int(row['packet_count'])
        b = int(row['byte_count'])
        r = risk_score(anomaly, pkt, b)
        if r >= 70.0:
            ip = row['src_ip']
            print('High risk detected', ip, r)
            res = defender.block_ip(ip)
            alert = {
                'time': int(time.time()),
                'src_ip': ip,
                'risk': r,
                'anomaly': anomaly,
                'action': res,
            }
            append_alert(alert)
            # optionally POST to dashboard webhook
            if dashboard_url:
                try:
                    import requests
                    requests.post(dashboard_url.rstrip('/') + '/events', json=alert, timeout=3)
                except Exception:
                    pass


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--flows', required=True)
    parser.add_argument('--model', default='models/isolation_model.joblib')
    parser.add_argument('--no-dry-run', dest='dry', action='store_false')
    parser.add_argument('--dashboard', dest='dashboard', default=None, help='dashboard base URL to POST events to, e.g. http://localhost:5010')
    args = parser.parse_args()
    run_sim(args.flows, args.model, dry_run=args.dry, dashboard_url=args.dashboard)
"""Simulated orchestrator runner that processes an existing flows CSV instead of capturing."""
import time
import json
from pathlib import Path
from ml.model import IsolationModel
from risk import risk_score
from defender import Defender
import pandas as pd

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


def run_sim(flows_csv: str, model_path: str = 'models/isolation_model.joblib', dry_run=True, dashboard_url: str = None):
    model = IsolationModel()
    model.load(model_path)
    df = pd.read_csv(flows_csv)
    if df.empty:
        print('No flows')
        return
    scores = model.score(df)
    df['anomaly'] = scores
    defender = Defender(dry_run=dry_run)

    for idx, row in df.iterrows():
        anomaly = float(row['anomaly'])
        pkt = int(row['packet_count'])
        b = int(row['byte_count'])
        r = risk_score(anomaly, pkt, b)
        if r >= 70.0:
            ip = row['src_ip']
            print('High risk detected', ip, r)
            res = defender.block_ip(ip)
            alert = {
                'time': int(time.time()),
                'src_ip': ip,
                'risk': r,
                'anomaly': anomaly,
                'action': res,
            }
            append_alert(alert)
            # optionally POST to dashboard webhook
            if dashboard_url:
                try:
                    import requests
                    requests.post(dashboard_url.rstrip('/') + '/events', json=alert, timeout=3)
                except Exception:
                    pass


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--flows', required=True)
    parser.add_argument('--model', default='models/isolation_model.joblib')
    parser.add_argument('--no-dry-run', dest='dry', action='store_false')
    parser.add_argument('--dashboard', dest='dashboard', default=None, help='dashboard base URL to POST events to, e.g. http://localhost:5010')
    args = parser.parse_args()
    run_sim(args.flows, args.model, dry_run=args.dry, dashboard_url=args.dashboard)
