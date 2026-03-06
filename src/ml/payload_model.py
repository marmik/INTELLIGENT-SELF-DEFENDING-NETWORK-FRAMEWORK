import numpy as np
import re
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from pathlib import Path

class PayloadClassifier:
    def __init__(self, model_path='models/payload_model.joblib', vectorizer_path='models/payload_vectorizer.joblib'):
        self.model_path = Path(model_path)
        self.vectorizer_path = Path(vectorizer_path)
        self.model = None
        self.vectorizer = None
        
        # Immediate regex-based exploit detection for SQLi and XSS
        self.exploit_patterns = [
            re.compile(r"union.*select", re.I),
            re.compile(r"select.*from", re.I),
            re.compile(r"<script.*?>", re.I),
            re.compile(r"javascript:", re.I),
            re.compile(r"onerror=", re.I),
            re.compile(r"onload=", re.I),
            re.compile(r"eval\(", re.I),
            re.compile(r"base64_decode", re.I),
            re.compile(r"/etc/passwd", re.I),
            re.compile(r"\.(exe|sh|bin|bat)$", re.I)
        ]

    def load(self):
        if self.model_path.exists() and self.vectorizer_path.exists():
            self.model = joblib.load(self.model_path)
            self.vectorizer = joblib.load(self.vectorizer_path)
            return True
        return False

    def predict_proba(self, payload_features: dict, raw_payload_text: str = "") -> float:
        """
        Hybrid prediction: ML if model exists, otherwise rule-based.
        """
        # 1. Rule-based check (High confidence)
        if raw_payload_text:
            for pattern in self.exploit_patterns:
                if pattern.search(raw_payload_text):
                    return 0.95
        
        # 2. ML Prediction
        if self.model and self.vectorizer and raw_payload_text:
            try:
                vec = self.vectorizer.transform([raw_payload_text])
                prob = self.model.predict_proba(vec)[0][1] # Probability of "Attack" class
                return float(prob)
            except: pass
            
        # 3. Simple heuristic based on extracted features
        # If entropy is high and suspicious keywords are present
        score = 0.0
        if payload_features.get('suspicious_keywords_count', 0) > 0:
            score += 0.4
        if payload_features.get('payload_entropy', 0) > 7.5:
            score += 0.3
        if payload_features.get('uri_length', 0) > 200:
            score += 0.2
        if payload_features.get('is_encoded_payload'):
            score += 0.1
            
        return min(0.9, score)

    def train(self, texts, labels):
        """
        Train the TF-IDF + Logistic Regression model.
        """
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4), max_features=5000)
        X = self.vectorizer.fit_transform(texts)
        self.model = LogisticRegression(C=1.0, class_weight='balanced')
        self.model.fit(X, labels)
        
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.vectorizer, self.vectorizer_path)
        print(f"Payload Model trained and saved to {self.model_path}")
