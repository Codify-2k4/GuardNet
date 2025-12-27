import pandas as pd
import numpy as np
import os
import joblib
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

# Define Paths
BASE_DIR = os.getcwd()
DATA_PATH = os.path.join(BASE_DIR, 'data/training_data.csv')
MODEL_PATH = os.path.join(BASE_DIR, 'src/ml/kmeans_model.joblib')
SCALER_PATH = os.path.join(BASE_DIR, 'src/ml/kmeans_scaler.joblib')

def train_kmeans():
    print("--- Starting K-Means Clustering ---")

    # 1. Load Real Malware Data (Tiny Packets)
    if os.path.exists(DATA_PATH):
        df_malware = pd.read_csv(DATA_PATH)
        print(f"Loaded {len(df_malware)} Malware samples.")
    else:
        print("Error: No data found.")
        return

    # Select features (Focusing on the ones you noticed: Size & Service)
    # We use all numeric features to be safe
    feature_cols = ['duration', 'protocol_type', 'service', 'flag', 
                    'src_bytes', 'dst_bytes', 'count', 'srv_count']
    
    # Ensure columns exist
    for col in feature_cols:
        if col not in df_malware.columns: df_malware[col] = 0
            
    X_malware = df_malware[feature_cols].values

    # 2. Generate Normal Data (Heavy Traffic)
    # This acts as the "Other" cluster
    print("Generating Synthetic Normal traffic...")
    n_normal = len(X_malware)
    df_normal = pd.DataFrame({
        'duration': np.random.uniform(5, 60, n_normal),
        'protocol_type': np.random.choice([1], n_normal),
        'service': np.random.choice([80, 443], n_normal),
        'flag': 0,
        'src_bytes': np.random.randint(5000, 50000, n_normal), # LARGE
        'dst_bytes': np.random.randint(5000, 50000, n_normal),
        'count': np.random.randint(10, 50, n_normal),
        'srv_count': np.random.randint(10, 50, n_normal)
    })
    X_normal = df_normal[feature_cols].values

    # 3. Combine Data
    X = np.concatenate((X_malware, X_normal), axis=0)
    
    # 4. Scale Data (Important for K-Means!)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 5. Train K-Means
    # We ask for 2 Clusters: One should end up being Malware, one Normal
    kmeans = KMeans(n_clusters=2, random_state=42, n_init=10)
    kmeans.fit(X_scaled)
    
    # 6. Analyze Clusters
    centers = scaler.inverse_transform(kmeans.cluster_centers_)
    
    print("\n--- Cluster Analysis ---")
    for i, center in enumerate(centers):
        # Index 4 is src_bytes
        avg_bytes = center[4] 
        print(f"Cluster {i}: Avg Src Bytes = {avg_bytes:.2f}")
        
        if avg_bytes < 1000:
            print(f"  -> IDENTIFIED AS: MALWARE (Matches your CSV profile)")
            malware_cluster = i
        else:
            print(f"  -> IDENTIFIED AS: NORMAL (Matches Heavy Traffic)")

    # 7. Save
    joblib.dump(kmeans, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"\nK-Means Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train_kmeans()