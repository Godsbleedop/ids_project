import joblib
import pandas as pd
import numpy as np
import os

class IDSDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoders = None
        self.feature_names = None
        self.load_model()

    def load_model(self):
        try:
            if not os.path.exists('models/ids_model.pkl'):
                print("Model not found. Please train the model first.")
                return False
            
            self.model = joblib.load('models/ids_model.pkl')
            self.scaler = joblib.load('models/scaler.pkl')
            self.label_encoders = joblib.load('models/label_encoders.pkl')
            self.feature_names = joblib.load('models/feature_names.pkl')
            print("Model loaded successfully!")
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False

    def prepare_features(self, packet_features):
        try:
            df = pd.DataFrame([packet_features])
            
            for col, le in self.label_encoders.items():
                if col in df.columns:
                    value = df[col].iloc[0]
                    if value not in le.classes_:
                        df[col] = le.classes_[0]
                    df[col] = le.transform(df[col])
            
            for feature in self.feature_names:
                if feature not in df.columns:
                    df[feature] = 0
            
            df = df[self.feature_names]
            return df
        except Exception as e:
            print(f"Error preparing features: {e}")
            return None

    def predict(self, packet_features):
        if self.model is None:
            return None, None
        
        try:
            df = self.prepare_features(packet_features)
            if df is None:
                return None, None
            
            scaled_features = self.scaler.transform(df)
            prediction = self.model.predict(scaled_features)[0]
            probability = self.model.predict_proba(scaled_features)[0]
            
            prediction = int(prediction)
            confidence = float(probability[1] if prediction == 1 else probability[0])
            
            return prediction, confidence
        except Exception as e:
            print(f"Error during prediction: {e}")
            return None, None

    def predict_batch(self, packets):
        results = []
        for packet in packets:
            features = packet.get('features', {})
            prediction, confidence = self.predict(features)
            
            is_attack_heuristic = self._heuristic_detection(features)
            
            final_prediction = 0
            final_confidence = 0.5
            
            if prediction == 1 and confidence is not None:
                if confidence > 0.75:
                    final_prediction = 1
                    final_confidence = confidence
                elif confidence > 0.55 and is_attack_heuristic:
                    final_prediction = 1
                    final_confidence = 0.70
                else:
                    final_prediction = 0
                    final_confidence = 1.0 - confidence
            elif prediction == 0 and is_attack_heuristic:
                final_prediction = 1
                final_confidence = 0.65
            else:
                final_prediction = 0
                final_confidence = confidence if confidence is not None else 0.8
            
            result = {
                'timestamp': float(packet.get('timestamp', 0)),
                'raw_info': {
                    'src': str(packet.get('raw_info', {}).get('src', 'unknown')),
                    'dst': str(packet.get('raw_info', {}).get('dst', 'unknown')),
                    'proto': str(packet.get('raw_info', {}).get('proto', 'unknown')),
                    'size': int(packet.get('raw_info', {}).get('size', 0))
                },
                'prediction': 'Attack' if final_prediction == 1 else 'Normal',
                'confidence': float(final_confidence),
                'is_attack': bool(final_prediction == 1)
            }
            results.append(result)
        
        return results
    
    def _heuristic_detection(self, features):
        """
        Heuristic detection with balanced thresholds
        """
        threat_score = 0
        
        # Land attack - always malicious
        if features.get('land', 0) == 1:
            return True
        
        # SYN flood detection
        serror_rate = features.get('serror_rate', 0)
        count = features.get('count', 0)
        if serror_rate > 0.75 and count > 80:
            threat_score += 3
        
        # Port scanning detection
        dst_host_count = features.get('dst_host_count', 0)
        dst_host_same_srv_rate = features.get('dst_host_same_srv_rate', 1.0)
        if dst_host_count > 40 and dst_host_same_srv_rate < 0.25:
            threat_score += 3
        
        # DoS - high connection count
        if count > 150:
            threat_score += 2
        
        # High rejection error rate
        rerror_rate = features.get('rerror_rate', 0)
        if rerror_rate > 0.8 and count > 40:
            threat_score += 2
        
        # Service scanning
        dst_host_diff_srv_rate = features.get('dst_host_diff_srv_rate', 0)
        if dst_host_diff_srv_rate > 0.65 and dst_host_count > 25:
            threat_score += 2
        
        # Low same-service rate (varied targeting)
        same_srv_rate = features.get('same_srv_rate', 1.0)
        if same_srv_rate < 0.15 and count > 40:
            threat_score += 1
        
        # Require score >= 4 for detection
        return threat_score >= 4

