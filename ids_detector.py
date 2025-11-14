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
            
            # Convert numpy types to Python native types
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
            
            # Ensure all values are JSON serializable (Python native types)
            result = {
                'timestamp': float(packet.get('timestamp', 0)),
                'raw_info': {
                    'src': str(packet.get('raw_info', {}).get('src', 'unknown')),
                    'dst': str(packet.get('raw_info', {}).get('dst', 'unknown')),
                    'proto': str(packet.get('raw_info', {}).get('proto', 'unknown')),
                    'size': int(packet.get('raw_info', {}).get('size', 0))
                },
                'prediction': 'Attack' if prediction == 1 else 'Normal',
                'confidence': float(confidence) if confidence is not None else 0.0,
                'is_attack': bool(prediction == 1)  # Convert to Python bool
            }
            
            results.append(result)
        
        return results
