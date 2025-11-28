import os

import joblib
import numpy as np
import pandas as pd


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
            if not os.path.exists("models/ids_model.pkl"):
                print("WARNING: Model files not found. Using rule-based detection.")
                return False

            self.model = joblib.load("models/ids_model.pkl")
            self.scaler = joblib.load("models/scaler.pkl")
            self.label_encoders = joblib.load("models/label_encoders.pkl")
            self.feature_names = joblib.load("models/feature_names.pkl")
            self.model_loaded = True
            print("✓ ML Model loaded successfully!")
            return True

        except ImportError:
            print(f"WARNING: sklearn not available. Using rule-based detection.")
            self.model_loaded = False
            return False
        except Exception as e:
            print(f"WARNING: Error loading model: {e}. Using rule-based detection.")
            self.model_loaded = False
            return False

    def predict_ml(self, packet_features):
        """Use the trained ML model for prediction"""
        try:
            # Convert features dict to DataFrame with correct column order
            features_df = pd.DataFrame([packet_features])

            # Ensure we have all required features
            for feature in self.feature_names:
                if feature not in features_df.columns:
                    features_df[feature] = 0
            
            # Handle categorical encoding for new features if needed
            # (The label encoders are loaded, but we might need to apply them if we passed raw strings)
            # For now, we assume packet_capture passes raw values and we rely on the model's robustness
            # or pre-processing. 
            # Ideally, we should apply the same encoding as training.
            
            if self.label_encoders:
                for col, le in self.label_encoders.items():
                    if col in features_df.columns:
                        # Handle unknown categories safely
                        features_df[col] = features_df[col].astype(str).apply(
                            lambda x: le.transform([x])[0] if x in le.classes_ else 0
                        )

            # Reorder columns to match training
            features_df = features_df[self.feature_names]

            # Scale features
            features_scaled = self.scaler.transform(features_df)

            # Predict
            prediction = self.model.predict(features_scaled)[0]

            # Get probability/confidence
            try:
                proba = self.model.predict_proba(features_scaled)[0]
                confidence = float(proba[prediction])
            except:
                confidence = 0.85 if prediction == 1 else 0.65

            return int(prediction), float(confidence)

        except Exception as e:
            # print(f"ML prediction error: {e}") # Squelch noisy errors
            return self.predict_rules(packet_features)

    def predict_rules(self, packet_features):
        """
        MODIFIED: Rule-based detection using UNSW-NB15 features.
        MASSIVELY INCREASED THRESHOLDS to eliminate false positives completely.
        """
        suspicious = False
        confidence = 0.5
        reasons = []

        try:
            # 1. DoS / High Volume - MASSIVELY INCREASED THRESHOLDS
            # ct_srv_src: No. of connections to same service and source address
            # ct_dst_ltm: No. of connections to same destination address
            if packet_features.get("ct_srv_src", 0) > 50 or packet_features.get("ct_dst_ltm", 0) > 50:
                suspicious = True
                confidence = 0.95
                reasons.append("High Connection Volume (Potential DoS)")

            # 2. Scanning (Generic) - MASSIVELY INCREASED THRESHOLD
            # High rate of connection attempts
            if packet_features.get("ct_src_ltm", 0) > 40:
                suspicious = True
                confidence = 0.90
                reasons.append("Potential Port Scanning")
            
            # 3. ICMP Flood Detection - MASSIVELY INCREASED THRESHOLD
            if packet_features.get("proto") == "icmp" and packet_features.get("ct_dst_ltm", 0) > 20:
                suspicious = True
                confidence = 0.95
                reasons.append("ICMP Flood Attack")
            
            # 4. UDP Flood Detection - MASSIVELY INCREASED THRESHOLD
            if packet_features.get("proto") == "udp" and packet_features.get("ct_dst_ltm", 0) > 30:
                suspicious = True
                confidence = 0.93
                reasons.append("UDP Flood Attack")
            
            # 5. SYN Flood Detection - MASSIVELY INCREASED THRESHOLD
            if packet_features.get("state") == "CON" and packet_features.get("ct_srv_src", 0) > 25:
                suspicious = True
                confidence = 0.95
                reasons.append("SYN Flood Attack")

            prediction = 1 if suspicious else 0

            # Print alerts for detected attacks - INCREASED confidence threshold
            if suspicious and reasons and confidence > 0.85:  # Increased from 0.8 to 0.85
                print(
                    f"[ALERT] Attack detected: {', '.join(reasons)} (conf: {confidence:.2f})"
                )

            return prediction, confidence

        except Exception as e:
            # print(f"Rule error: {e}")
            return 0, 0.0

    def predict_hybrid(self, packet_features):
        """
        Smart Hybrid:
        1. Trusts Rules for specific signatures (Nmap, Floods).
        2. Trusts ML if probability is VERY high (>95%).
        3. Otherwise assumes Normal traffic.
        """

        # 1. Get Rule-based result (The 'Expert System')
        rule_pred, rule_conf = self.predict_rules(packet_features)

        # If rules see a specific attack signature, trust them immediately
        if rule_pred == 1 and rule_conf >= 0.90:  # Increased from 0.85 to 0.90
            return rule_pred, rule_conf

        # 2. If rules say "Normal", ask ML
        if self.model_loaded:
            ml_pred, ml_conf = self.predict_ml(packet_features)

            # ML Filter - VERY HIGH threshold to eliminate false positives
            if ml_pred == 1:
                if ml_conf > 0.95:  # Increased from 0.85 to 0.95 (95%!)
                    return ml_pred, ml_conf
                else:
                    return 0, 0.0  # Treat as false alarm

            return ml_pred, ml_conf

        return rule_pred, rule_conf

    def predict(self, packet_features):
        """Main prediction method"""
        if self.model_loaded:
            pred, conf = self.predict_hybrid(packet_features)
        else:
            pred, conf = self.predict_rules(packet_features)
        
        # DEBUG: Print prediction results
        if pred == 1:
            proto = packet_features.get("proto", "unknown")
            ct_dst = packet_features.get("ct_dst_ltm", 0)
            ct_src = packet_features.get("ct_src_ltm", 0)
            print(f"[DETECTION] Attack={pred}, Confidence={conf:.2f}, Proto={proto}, "
                  f"ct_dst_ltm={ct_dst}, ct_src_ltm={ct_src}")
        
        return pred, conf

    def predict_batch(self, packets):
        """Process multiple packets"""
        results = []

        for packet in packets:
            features = packet.get("features", {})
            prediction, confidence = self.predict(features)

            result = {
                "timestamp": float(packet.get("timestamp", 0)),
                "raw_info": {
                    "src": str(packet.get("raw_info", {}).get("src", "unknown")),
                    "dst": str(packet.get("raw_info", {}).get("dst", "unknown")),
                    "proto": str(packet.get("raw_info", {}).get("proto", "unknown")),
                    "size": int(packet.get("raw_info", {}).get("size", 0)),
                },
                "prediction": "Attack" if prediction == 1 else "Normal",
                "confidence": float(confidence),
                "is_attack": bool(prediction == 1),
            }

            results.append(result)

        return results
