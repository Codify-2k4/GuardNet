import joblib
import numpy as np
import pandas as pd
import os

BASE_DIR = os.getcwd()
MODEL_PATH = os.path.join(BASE_DIR, 'src/ml/kmeans_model.joblib')
SCALER_PATH = os.path.join(BASE_DIR, 'src/ml/kmeans_scaler.joblib')

def check_packet(packet_dict):
    # Load Model
    kmeans = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    # Prepare Data
    feature_cols = ['duration', 'protocol_type', 'service', 'flag', 
                    'src_bytes', 'dst_bytes', 'count', 'srv_count']
    
    df = pd.DataFrame([packet_dict])
    # Ensure cols
    for col in feature_cols:
        if col not in df.columns: df[col] = 0
    
    X = df[feature_cols].values
    X_scaled = scaler.transform(X)

    # Predict Cluster
    cluster_id = kmeans.predict(X_scaled)[0]
    
    # Calculate Distance to that cluster center (The "Uniqueness" Score)
    center = kmeans.cluster_centers_[cluster_id]
    distance = np.linalg.norm(X_scaled - center)

    # Logic to interpret results
    # We inspect the centroid to know if this cluster ID is the "Malware" one
    # (In training, we saw Small Bytes = Malware. Let's assume we saved that mapping)
    # For now, we dynamically check the centroid size
    centroid_real_values = scaler.inverse_transform([center])[0]
    avg_bytes = centroid_real_values[4] # src_bytes index
    
    cluster_name = "Possible Malware" if avg_bytes < 1000 else "Normal Traffic"
    
    print(f"\n--- Packet Analysis ---")
    print(f"Packet Size: {packet_dict['src_bytes']} bytes")
    print(f"Assigned Cluster: {cluster_id} ({cluster_name})")
    print(f"Distance to Center: {distance:.4f}")

    # THE "ISOLATION" LOGIC
    if distance > 2.0: # Threshold for "Far away"
        print(">>> ALERT: UNIQUE PATTERN DETECTED! Isolating for review...")
        # Code to save to 'isolated_packets.csv' would go here
    else:
        print(">>> Pattern matches known cluster.")

# --- Test with 3 Scenarios ---
if __name__ == "__main__":
    print("Loading models...")
    
    # 1. Known Malware (Tiny)
    pkt_malware = {'duration': 0.1, 'protocol_type': 1, 'service': 0, 'flag': 0, 
                   'src_bytes': 43, 'dst_bytes': 0, 'count': 1, 'srv_count': 1}
    
    # 2. Known Normal (Huge)
    pkt_normal = {'duration': 10, 'protocol_type': 1, 'service': 443, 'flag': 0, 
                  'src_bytes': 20000, 'dst_bytes': 20000, 'count': 20, 'srv_count': 20}
    
    # 3. NEW/UNIQUE Pattern (Medium size, weird service - e.g. Port 6667 IRC Botnet)
    # This doesn't fit 'Tiny' OR 'Huge' perfectly
    pkt_weird = {'duration': 5, 'protocol_type': 1, 'service': 6667, 'flag': 0, 
                 'src_bytes': 3000, 'dst_bytes': 500, 'count': 5, 'srv_count': 5}

    print("\nTest 1: Known Malware Packet")
    check_packet(pkt_malware)
    
    print("\nTest 2: Known Normal Packet")
    check_packet(pkt_normal)
    
    print("\nTest 3: Weird/Unique Packet")
    check_packet(pkt_weird)