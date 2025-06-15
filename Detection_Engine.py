# Detection_Engine.py
from sklearn.ensemble import IsolationForest
import numpy as np
import pandas as pd

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.signature_rules = self.load_signature_rules()
        self.training_data = self.load_training_data()

        # Fit the model on initialization if training data is available
        if self.training_data is not None:
            self.train_anomaly_detector(self.training_data)

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and
                    features['packet_rate'] > 50
                )
            }
        }

    def load_training_data(self):
        try:
            normal_data = pd.DataFrame({
                'packet_size': [100, 200, 150, 300, 180, 220],
                'packet_rate': [50, 60, 55, 70, 65, 62],
                'byte_rate': [5000, 6000, 5500, 7000, 6400, 6100]
            })
            return normal_data[['packet_size', 'packet_rate', 'byte_rate']].values
        except Exception as e:
            print("[ERROR] Failed to load training data:", e)
            return None

    def train_anomaly_detector(self, normal_traffic_data):
        self.anomaly_detector.fit(normal_traffic_data)

    def detect_threat(self, features):
        threats = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        # Anomaly-based detection
        try:
            feature_vector = np.array([[
                features['packet_size'],
                features['packet_rate'],
                features['byte_rate'],
            ]])
            anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
            if anomaly_score < -0.5:
                threats.append({
                    'type': 'anomaly',
                    'score': anomaly_score,
                    'confidence': min(1.0, abs(anomaly_score))
                })
        except Exception as e:
            print("[ERROR] Isolation Forest not fitted or invalid input:", e)

        return threats
