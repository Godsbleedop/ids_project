import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

print("Starting model training...")

column_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

def download_nsl_kdd():
    import requests
    
    train_url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
    test_url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt"
    
    print("Downloading NSL-KDD training dataset...")
    response = requests.get(train_url)
    with open('data/KDDTrain+.txt', 'wb') as f:
        f.write(response.content)
    
    print("Downloading NSL-KDD test dataset...")
    response = requests.get(test_url)
    with open('data/KDDTest+.txt', 'wb') as f:
        f.write(response.content)
    
    print("Dataset downloaded successfully!")

def load_and_preprocess_data():
    if not os.path.exists('data/KDDTrain+.txt'):
        download_nsl_kdd()
    
    print("Loading training data...")
    train_data = pd.read_csv('data/KDDTrain+.txt', names=column_names, header=None)
    
    print("Loading test data...")
    test_data = pd.read_csv('data/KDDTest+.txt', names=column_names, header=None)
    
    train_data = train_data.drop(['difficulty'], axis=1)
    test_data = test_data.drop(['difficulty'], axis=1)
    

    train_data['label'] = train_data['label'].apply(lambda x: 0 if x == 'normal' else 1)
    test_data['label'] = test_data['label'].apply(lambda x: 0 if x == 'normal' else 1)
    
    return train_data, test_data

def encode_categorical_features(train_data, test_data):
    print("Encoding categorical features...")
    
    categorical_columns = ['protocol_type', 'service', 'flag']
    
    label_encoders = {}
    for col in categorical_columns:
        le = LabelEncoder()
        train_data[col] = le.fit_transform(train_data[col])
        
        test_data[col] = test_data[col].apply(lambda x: x if x in le.classes_ else le.classes_[0])
        test_data[col] = le.transform(test_data[col])
        
        label_encoders[col] = le
    
    joblib.dump(label_encoders, 'models/label_encoders.pkl')
    
    return train_data, test_data

def train_model(train_data, test_data):
    print("Preparing training data...")
    
    X_train = train_data.drop(['label'], axis=1)
    y_train = train_data['label']
    
    X_test = test_data.drop(['label'], axis=1)
    y_test = test_data['label']
    
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    joblib.dump(scaler, 'models/scaler.pkl')
    
    print("Training Random Forest model...")
    model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
    model.fit(X_train_scaled, y_train)
    
    print("Evaluating model...")
    train_score = model.score(X_train_scaled, y_train)
    test_score = model.score(X_test_scaled, y_test)
    
    print(f"Training Accuracy: {train_score:.4f}")
    print(f"Testing Accuracy: {test_score:.4f}")
    
    joblib.dump(model, 'models/ids_model.pkl')
    
    feature_names = X_train.columns.tolist()
    joblib.dump(feature_names, 'models/feature_names.pkl')
    
    print("Model saved successfully!")

if __name__ == "__main__":
    train_data, test_data = load_and_preprocess_data()
    train_data, test_data = encode_categorical_features(train_data, test_data)
    train_model(train_data, test_data)
    print("Training complete!")
