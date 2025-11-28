import os
import sys

try:
    import joblib
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder, StandardScaler
except ImportError as e:
    print(f"\n[!] Critical Error: Missing dependency '{e.name}'")
    print(f"[-] Please run: pip install -r requirements.txt")
    print(f"[-] Or install specifically: pip install {e.name}\n")
    sys.exit(1)

print("Starting model training...")

def load_and_preprocess_data():
    print("Loading UNSW-NB15 dataset...")
    if os.path.exists("data/unsw_nb15_train.csv"):
        df = pd.read_csv("data/unsw_nb15_train.csv")
    elif os.path.exists("data/unsw_dataset.csv"):
        df = pd.read_csv("data/unsw_dataset.csv")
    else:
        print("Error: UNSW-NB15 dataset not found. Please run download_unsw.py")
        return None, None

    # UNSW-NB15 Preprocessing
    if 'id' in df.columns:
        df = df.drop(['id'], axis=1)
        
    if 'attack_cat' in df.columns:
        df = df.drop(['attack_cat'], axis=1)
        
    # Split into train/test
    train_data, test_data = train_test_split(df, test_size=0.2, random_state=42)
    
    return train_data, test_data


def encode_categorical_features(train_data, test_data):
    print("Encoding categorical features...")

    # Identify categorical columns (object type)
    categorical_columns = train_data.select_dtypes(include=['object']).columns.tolist()
    
    # Remove label from categorical if present (it shouldn't be, but just in case)
    if 'label' in categorical_columns:
        categorical_columns.remove('label')

    label_encoders = {}
    for col in categorical_columns:
        le = LabelEncoder()
        # Handle unknown values in test set
        train_data[col] = le.fit_transform(train_data[col].astype(str))
        
        # For test data, map unknown to a default or handle error
        # Simple approach: fit on combined data for encoding consistency in this demo
        # But correct way is to handle unknowns. Let's use a safe approach:
        # Re-fit on all known values from both sets for the encoder to know them
        # (In production, you'd handle 'unknown' token)
        le.fit(pd.concat([train_data[col], test_data[col]]).astype(str))
        
        train_data[col] = le.transform(train_data[col].astype(str))
        test_data[col] = le.transform(test_data[col].astype(str))

        label_encoders[col] = le

    joblib.dump(label_encoders, "models/label_encoders.pkl")

    return train_data, test_data


def train_model(train_data, test_data):
    print("Preparing training data...")

    X_train = train_data.drop(["label"], axis=1)
    y_train = train_data["label"]

    X_test = test_data.drop(["label"], axis=1)
    y_test = test_data["label"]

    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    joblib.dump(scaler, "models/scaler.pkl")

    print("Training Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=100, max_depth=20, random_state=42, n_jobs=-1
    )
    model.fit(X_train_scaled, y_train)

    print("Evaluating model...")
    train_score = model.score(X_train_scaled, y_train)
    test_score = model.score(X_test_scaled, y_test)

    print(f"Training Accuracy: {train_score:.4f}")
    print(f"Testing Accuracy: {test_score:.4f}")

    joblib.dump(model, "models/ids_model.pkl")

    feature_names = X_train.columns.tolist()
    joblib.dump(feature_names, "models/feature_names.pkl")

    print("Model saved successfully!")


if __name__ == "__main__":
    train_data, test_data = load_and_preprocess_data()
    train_data, test_data = encode_categorical_features(train_data, test_data)
    train_model(train_data, test_data)
    print("Training complete!")
