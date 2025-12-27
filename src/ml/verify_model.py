import os
import numpy as np
import pandas as pd
import tensorflow as tf
import joblib
from sklearn.metrics import classification_report, confusion_matrix
from src.core.preprocessor import DataPreprocessor

# 1. Setup Paths
BASE_DIR = os.getcwd()
MODEL_PATH = os.path.join(BASE_DIR, 'src/ml/guardnet_lstm.keras')
SCALER_PATH = os.path.join(BASE_DIR, 'src/ml/scaler.joblib')
DATA_PATH = os.path.join(BASE_DIR, 'data/training_data.csv')

def verify():
    print("--- Starting Model Verification ---")

    # 2. Load Model & Scaler
    try:
        model = tf.keras.models.load_model(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        print("✅ Model and Scaler loaded successfully.")
    except Exception as e:
        print(f"❌ Critical Error: Could not load model. {e}")
        return

    # 3. Load Data
    if os.path.exists(DATA_PATH):
        print(f"Loading real data from {DATA_PATH}...")
        df = pd.read_csv(DATA_PATH)
        
        feature_cols = ['duration', 'protocol_type', 'service', 'flag', 
                        'src_bytes', 'dst_bytes', 'count', 'srv_count']
        
        # Ensure correct columns exist
        for col in feature_cols:
            if col not in df.columns:
                df[col] = 0

        X = df[feature_cols].values
        
        # Check for labels
        if 'label' not in df.columns:
            print("⚠️ No 'label' column found. Generating dummy labels for pipeline test.")
            print("(Note: Accuracy metrics will be meaningless, checking prediction flow only)")
            y = np.random.randint(0, 2, size=len(df)) 
        else:
            y = df['label'].values
    else:
        print("⚠️ Real data not found. Using synthetic data.")
        from sklearn.datasets import make_classification
        X, y = make_classification(n_samples=500, n_features=8, random_state=42)

    # 4. Preprocess
    # FIX: The 'scaler' object is actually the DataPreprocessor class.
    # Its .transform() method AUTOMATICALLY reshapes to 3D. We don't need to do it again.
    X_processed = scaler.transform(X)
    
    print(f"Data Shape verified: {X_processed.shape}") # Should be (Samples, 1, 8)

    # 5. Predict
    print(f"\nRunning predictions on {len(X)} samples...")
    y_pred_probs = model.predict(X_processed, verbose=0)
    y_pred = (y_pred_probs > 0.5).astype(int)

    # 6. Report
    print("\n--- Verification Results ---")
    print(confusion_matrix(y, y_pred))
    print("\nClassification Report:")
    print(classification_report(y, y_pred, zero_division=0))

if __name__ == "__main__":
    verify()