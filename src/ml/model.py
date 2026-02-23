import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import pandas as pd
from pathlib import Path


class EnsembleModel:
    def __init__(self):
        # Ensemble of two IsolationForests with different sensitivities
        # IF-1: High Sensitivity (Aggressive)
        self.pipeline1 = Pipeline([
            ('scaler', StandardScaler()),
            ('clf', IsolationForest(n_estimators=100, contamination='auto', random_state=42))
        ])
        # IF-2: Low Sensitivity (Conservative)
        self.pipeline2 = Pipeline([
            ('scaler', StandardScaler()),
            ('clf', IsolationForest(n_estimators=200, contamination=0.01, random_state=7))
        ])

    def train(self, flows_csv: str, save_path: str):
        df = pd.read_csv(flows_csv)
        features = self._prepare(df)
        self.pipeline1.fit(features)
        self.pipeline2.fit(features)
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"m1": self.pipeline1, "m2": self.pipeline2}, save_path)
        return save_path

    def load(self, path: str):
        bundle = joblib.load(path)
        self.pipeline1 = bundle["m1"]
        self.pipeline2 = bundle["m2"]
        return self.pipeline1

    def score(self, df: pd.DataFrame):
        X = self._prepare(df)
        
        # Get raw scores from both voters
        s1 = -self.pipeline1.named_steps['clf'].score_samples(X)
        s2 = -self.pipeline2.named_steps['clf'].score_samples(X)
        
        # Consensus Voting: Average weighted towards the conservative model
        # This helps suppress noise that only the aggressive model catches
        consensus = (0.4 * s1) + (0.6 * s2)
        
        return consensus.clip(0, 1)

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
