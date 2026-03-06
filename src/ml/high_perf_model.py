import torch
import torch.nn as nn
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from .payload_model import PayloadClassifier

class CICDetectorDNN(nn.Module):
    def __init__(self, input_size, num_classes):
        super(CICDetectorDNN, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(0.3),
            
            nn.Linear(512, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.3),
            
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.2),
            
            nn.Linear(128, 64),
            nn.ReLU(),
            
            nn.Linear(64, num_classes)
        )
        
    def forward(self, x):
        return self.network(x)

class AnomalyCalibrator:
    """V16.6: Environment-Specific Anomaly Normalization.
    Converts raw model scores to percentile ranks based on local benign baseline.
    """
    def __init__(self, window_size: int = 2000):
        self.window_size = window_size
        self.min_baseline = 300 # V16.7: Warm-up threshold
        self.window = [] 
        self.is_frozen = False
        self.path = Path('models/cic_calibration_v2.joblib')
        self.load()

    def load(self):
        if self.path.exists():
            try:
                data = joblib.load(self.path)
                self.window = data.get('window', [])
                if not isinstance(self.window, list):
                    self.window = list(self.window)
            except:
                self.window = []
    
    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            joblib.dump({'window': self.window}, self.path)
        except Exception:
            # Persistence is best-effort only; inference must continue.
            pass

    def update(self, scores):
        if self.is_frozen: return
        self.window.extend(scores)
        if len(self.window) > self.window_size:
            self.window = self.window[-self.window_size:]
        
    def calibrate(self, raw_score):
        # V16.7: Cold-Start / Warm-up Logic
        if len(self.window) < self.min_baseline:
            # V16.7 Final Refinement: Raw scores must be aggressively dampened (0.1x) during warm-up
            # for suspected infrastructure to prevent blocks.
            return max(0.01, min(0.4, raw_score * 0.1))
        
        # Percentile Rank using searchsorted (more efficient and handles ties better)
        sorted_window = np.sort(self.window)
        rank = np.searchsorted(sorted_window, raw_score) / len(self.window)
        
        # Safety clamp to prevent zero-fallout or absolute 1.0 instability
        calibrated = np.clip(rank, 0.01, 0.99)
        return calibrated

    def get_adaptive_scaling(self):
        """Derive scaling factor (0.4-0.8) from rolling variance."""
        if len(self.window) < self.min_baseline: return 0.5
        variance = np.var(self.window)
        scaling = max(0.4, min(0.8, 0.8 - (variance * 2.0)))
        return scaling

class HighPerfInferenceEngine:
    def __init__(self, model_path='models/cic_model_v1.pt', 
                 scaler_path='models/cic_scaler_v1.joblib', 
                 encoder_path='models/cic_label_encoder_v1.joblib',
                 feature_path='models/cic_features_v1.joblib',
                 calibration_path='models/cic_calibration_v1.joblib',
                 priors_path='models/cic_priors_v1.joblib',
                 decision_path='models/cic_decision_metadata_v1.joblib'):
        self.device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
        self.scaler = joblib.load(scaler_path)
        self.le = joblib.load(encoder_path)
        self.feature_names = joblib.load(feature_path)
        
        self.calibrator = AnomalyCalibrator()
        self.payload_model = PayloadClassifier()
        self.payload_model.load()
        
        self.calib_meta = joblib.load(calibration_path)
        self.temperature = self.calib_meta.get('temperature', 1.0)
        
        self.priors = joblib.load(priors_path)
        self.decision_meta = joblib.load(decision_path)
        self.ensemble_weights = self.calib_meta.get('ensemble_weights', {'dnn': 1.0, 'hgb': 0.0})
        self.hgb_model = None
        hgb_path = Path('models/cic_hgb_model_v1.joblib')
        if hgb_path.exists():
            try:
                self.hgb_model = joblib.load(hgb_path)
                print("Loaded optional boosted model for ensemble inference")
            except Exception:
                self.hgb_model = None
        
        input_size = len(self.feature_names)
        num_classes = len(self.le.classes_)
        
        self.model = CICDetectorDNN(input_size, num_classes).to(self.device)
        self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        self.model.eval()
        
        print(f"CIC Decision-Optimized Engine Initialized on {self.device}")

    def predict(self, df):
        from .utils import is_known_infra
        X = df[self.feature_names].fillna(0)
        X_scaled = self.scaler.transform(X)
        X_tensor = torch.tensor(X_scaled, dtype=torch.float32).to(self.device)
        
        with torch.no_grad():
            logits = self.model(X_tensor).cpu().numpy()
            adjusted_logits = logits - 1.0 * np.log(self.priors + 1e-12)
            calibrated_logits = adjusted_logits / self.temperature
            final_probs = np.exp(calibrated_logits) / np.sum(np.exp(calibrated_logits), axis=1, keepdims=True)

        # Optional blended ensemble: DNN + boosted tree
        if self.hgb_model is not None:
            try:
                hgb_probs = self.hgb_model.predict_proba(X_scaled)
                dnn_w = float(self.ensemble_weights.get('dnn', 1.0))
                hgb_w = float(self.ensemble_weights.get('hgb', 0.0))
                denom = max(1e-6, dnn_w + hgb_w)
                dnn_w /= denom
                hgb_w /= denom
                if hgb_probs.shape == final_probs.shape:
                    final_probs = (dnn_w * final_probs) + (hgb_w * hgb_probs)
            except Exception:
                pass
            
        final_labels = []
        final_anomaly_scores = []
        payload_scores = []
        benign_idx = list(self.le.classes_).index('BENIGN')
        
        benign_scores_for_update = []
        raw_anomaly_scores = []
        
        for i, p_row in enumerate(final_probs):
            best_idx = np.argmax(p_row)
            best_label = self.le.classes_[best_idx]
            ip = df['src_ip'].iloc[i] if 'src_ip' in df.columns else None
            
            raw_anomaly = 1.0 - p_row[benign_idx]
            raw_anomaly_scores.append(raw_anomaly)
            
            anomaly_score = self.calibrator.calibrate(raw_anomaly)
            
            # V16.7 Breakdown of Calibration Starvation
            # We must learn that infrastructure IPs are part of the baseline even if they look anomalous
            if best_label == 'BENIGN' or is_known_infra(ip):
                benign_scores_for_update.append(raw_anomaly)
            
            payload_feats = {
                'payload_entropy': df['payload_entropy'].iloc[i] if 'payload_entropy' in df.columns else 0.0,
                'uri_length': df['uri_length'].iloc[i] if 'uri_length' in df.columns else 0,
                'suspicious_keywords_count': df['suspicious_keywords_count'].iloc[i] if 'suspicious_keywords_count' in df.columns else 0,
                'is_encoded_payload': df['is_encoded_payload'].iloc[i] if 'is_encoded_payload' in df.columns else 0
            }
            try:
                payload_score = self.payload_model.predict_proba(payload_feats)
            except:
                payload_score = 0.1
            
            final_labels.append(best_label)
            final_anomaly_scores.append(float(anomaly_score))
            payload_scores.append(float(payload_score))
            
            # Bootstrap Phase: Gather broader baseline samples
            if len(self.calibrator.window) < self.calibrator.min_baseline * 2:
                if best_label == 'BENIGN' or raw_anomaly < 0.8:
                    benign_scores_for_update.append(raw_anomaly)
        
        if benign_scores_for_update:
            self.calibrator.update(list(set(benign_scores_for_update)))
            if len(self.calibrator.window) % 50 == 0:
                self.calibrator.save()

        return np.array(final_anomaly_scores), np.array(raw_anomaly_scores), np.array(final_labels), np.array(payload_scores)
