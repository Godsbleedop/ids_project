import pandas as pd
import numpy as np
import os

class IDSDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoders = None
        self.feature_names = None
        self.model_loaded = False
        self.load_model()
        
    def load_model(self):
        try:
            import joblib
            import sklearn
            
            if not os.path.exists('models/ids_model.pkl'):
                print("WARNING: Model files not found. Using rule-based detection.")
                return False
                
            self.model = joblib.load('models/ids_model.pkl')
            self.scaler = joblib.load('models/scaler.pkl')
            self.label_encoders = joblib.load('models/label_encoders.pkl')
            self.feature_names = joblib.load('models/feature_names.pkl')
            self.model_loaded = True
            print("Model loaded successfully!")
            return True
            
        except ImportError as e:
            print(f"WARNING: sklearn not available. Using rule-based detection.")
            self.model_loaded = False
            return False
        except Exception as e:
            print(f"WARNING: Error loading model. Using rule-based detection.")
            self.model_loaded = False
            return False
    
    def predict_rules(self, packet_features):
        suspicious = False
        confidence = 0.5
        
        try:
            if packet_features.get('flag') == 'S0':
                suspicious = True
                confidence = 0.85
            
            if packet_features.get('count', 0) > 15:
                suspicious = True
                confidence = max(confidence, 0.75)
            
            if packet_features.get('dst_host_count', 0) > 50:
                suspicious = True
                confidence = max(confidence, 0.90)
            
            if packet_features.get('serror_rate', 0) > 0.5:
                suspicious = True
                confidence = max(confidence, 0.70)
            
            if packet_features.get('srv_count', 0) > 20:
                suspicious = True
                confidence = max(confidence, 0.65)
            
            if packet_features.get('diff_srv_rate', 0) > 0.8:
                suspicious = True
                confidence = max(confidence, 0.80)
            
            prediction = 1 if suspicious else 0
            return prediction, confidence
            
        except Exception as e:
            return 0, 0.5
    
    def predict(self, packet_features):
        return self.predict_rules(packet_features)
    
    def predict_batch(self, packets):
        results = []
        
        for packet in packets:
            features = packet.get('features', {})
            prediction, confidence = self.predict(features)
            
            result = {
                'timestamp': float(packet.get('timestamp', 0)),
                'raw_info': {
                    'src': str(packet.get('raw_info', {}).get('src', 'unknown')),
                    'dst': str(packet.get('raw_info', {}).get('dst', 'unknown')),
                    'proto': str(packet.get('raw_info', {}).get('proto', 'unknown')),
                    'size': int(packet.get('raw_info', {}).get('size', 0))
                },
                'prediction': 'Attack' if prediction == 1 else 'Normal',
                'confidence': float(confidence),
                'is_attack': bool(prediction == 1)
            }
            
            results.append(result)
        
        return results
