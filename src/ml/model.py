import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import pandas as pd
from pathlib import Path


class IsolationModel:
    def __init__(self):
        self.pipeline = Pipeline([
            ('scaler', StandardScaler()),
            ('clf', IsolationForest(n_estimators=100, contamination='auto', random_state=42))
        ])

    def train(self, flows_csv: str, save_path: str):
        df = pd.read_csv(flows_csv)
        features = self._prepare(df)
        self.pipeline.fit(features)
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, save_path)
        return save_path

    def load(self, path: str):
        self.pipeline = joblib.load(path)
        return self.pipeline

    def score(self, df: pd.DataFrame):
        X = self._prepare(df)
        raw = self.pipeline.named_steps['clf'].score_samples(X)
        # Normalize via clipping - score_samples is usually between -1.0 and 0.0
        # We want 0 (normal) to 1 (anomaly)
        return (-raw).clip(0, 1)

    def _prepare(self, df: pd.DataFrame):
        # ISDNF Expanded Feature Set (39 Features)
        features = [
            'mac_ip_mismatch', 'multiple_ips_per_mac',
            'ttl_mean', 'ttl_var', 'abnormal_ttl_count', 'fragmentation_rate',
            'syn_count', 'ack_count', 'fin_count', 'rst_count', 'incomplete_handshakes',
            'rst_syn_ratio', 'avg_tcp_window',
            'udp_burst_rate', 'udp_flood_indicator',
            'icmp_flood_rate', 'echo_req_res_ratio',
            'payload_entropy', 'header_payload_ratio',
            'iat_mean', 'iat_min', 'iat_max', 'iat_std',
            'pps', 'bps', 'burst_detection',
            'flow_duration', 'total_packets', 'total_bytes',
            'avg_packet_size', 'min_packet_size', 'max_packet_size',
            'fwd_bwd_packet_ratio', 'one_sided_flow',
            'unique_ports_per_sec', 'connection_attempt_rate',
            'beaconing_score', 'out_in_byte_ratio', 'pct_incomplete_handshakes'
        ]
        X = df[features].fillna(0).astype(float)
        return X
