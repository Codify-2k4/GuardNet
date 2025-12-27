import os
import numpy as np
import joblib
from sklearn.datasets import make_classification
from src.ml.dl_model import build_lstm_model
from src.core.preprocessor import DataPreprocessor
import pandas as pd # Ensure pandas is imported

# Define paths
MODEL_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(MODEL_DIR, 'guardnet_lstm.keras') # Keras format
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.joblib')

def train_lstm_pipeline():
    print("Initializing Deep Learning Pipeline...")
    
    CSV_PATH = os.path.join(os.getcwd(), 'data', 'training_data.csv')

    # 1. Load Real Data (Malicious)
    if os.path.exists(CSV_PATH):
        print(f"Loading Malicious data from {CSV_PATH}...")
        df_malicious = pd.read_csv(CSV_PATH)
        # Select features
        feature_cols = ['duration', 'protocol_type', 'service', 'flag', 
                        'src_bytes', 'dst_bytes', 'count', 'srv_count']
        
        # Fill missing
        for col in feature_cols:
            if col not in df_malicious.columns: df_malicious[col] = 0
        
        # ... (Load df_malicious as before) ...
        
        X_malicious = df_malicious[feature_cols].values
        y_malicious = np.ones(len(X_malicious)) # Label = 1 (Attack)

        # --- CORRECTED LOGIC: Normal = Heavy Traffic ---
        # Since your Malicious data is tiny (avg 43 bytes), 
        # we make Normal data BIGGER to distinguish it.
        print("Generating 'Heavy Usage' Normal traffic to contrast with tiny attacks...")
        n_normal = len(X_malicious)
        
        df_normal = pd.DataFrame({
            'duration': np.random.uniform(1.0, 60.0, n_normal),      # Longer sessions
            'protocol_type': np.random.choice([1], n_normal),        # TCP
            'service': np.random.choice([80, 443], n_normal),        # HTTP/HTTPS
            'flag': np.zeros(n_normal),
            # Normal traffic (YouTube, Downloads) has MORE bytes than your attack data
            'src_bytes': np.random.randint(2000, 50000, n_normal),   
            'dst_bytes': np.random.randint(2000, 50000, n_normal),   
            'count': np.random.randint(5, 50, n_normal),             # Active flows
            'srv_count': np.random.randint(5, 50, n_normal)
        })
        
        X_normal = df_normal[feature_cols].values
        y_normal = np.zeros(n_normal) # Label = 0 (Normal)
        
        # ... (Combine and Save as before) ...

        # Combine
        X = np.concatenate((X_malicious, X_normal), axis=0)
        y = np.concatenate((y_malicious, y_normal), axis=0)
        
        # Shuffle
        from sklearn.utils import shuffle
        X, y = shuffle(X, y, random_state=42)

        
    else:
        print("Real data not found. Generating synthetic data...")
        X, y = make_classification(n_samples=1000, n_features=8, n_informative=8, n_redundant=0, random_state=42)

    
    # 2. Preprocess (Scale & Reshape)
    preprocessor = DataPreprocessor()
    preprocessor.fit(X)
    X_processed = preprocessor.transform(X) # Returns (1000, 1, 8)
    
    print(f"Data Shape: {X_processed.shape}") # Should be (1000, 1, 8)

    # 3. Build Model
    input_shape = (X_processed.shape[1], X_processed.shape[2]) # (1, 8)
    model = build_lstm_model(input_shape)

    # 4. Train
    print("Starting LSTM Training...")
    model.fit(X_processed, y, epochs=5, batch_size=32, validation_split=0.2)

    # 5. Save Artifacts
    model.save(MODEL_PATH)
    joblib.dump(preprocessor, SCALER_PATH)
    
    print(f"LSTM Model saved to {MODEL_PATH}")
    print(f"Scaler saved to {SCALER_PATH}")

if __name__ == "__main__":
    train_lstm_pipeline()