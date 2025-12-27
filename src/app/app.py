from flask import Flask, render_template, jsonify, request
import joblib
import os
import numpy as np
import tensorflow as tf
from src.utils.logger import setup_logger
from datetime import datetime

app = Flask(__name__)
logger = setup_logger("webapp")

# --- CONFIGURATION ---
# Your friend needs to send this key in headers
API_KEY = "guardnet-secret-access-token"

# --- GLOBAL MEMORY ---
RECENT_LOGS = []
STATS = {"normal": 0, "malicious": 0, "anomalies": 0}

# --- LOAD MODELS ---
BASE_DIR = os.getcwd()
ML_DIR = os.path.join(BASE_DIR, 'src/ml')
LSTM_PATH = os.path.join(ML_DIR, 'guardnet_lstm.keras')
LSTM_SCALER_PATH = os.path.join(ML_DIR, 'scaler.joblib')
KMEANS_PATH = os.path.join(ML_DIR, 'kmeans_model.joblib')
KMEANS_SCALER_PATH = os.path.join(ML_DIR, 'kmeans_scaler.joblib')

try:
    if not os.path.exists(LSTM_PATH): raise FileNotFoundError("Model files missing")
    
    # Load Models
    lstm_model = tf.keras.models.load_model(LSTM_PATH)
    lstm_scaler = joblib.load(LSTM_SCALER_PATH)
    kmeans_model = joblib.load(KMEANS_PATH)
    kmeans_scaler = joblib.load(KMEANS_SCALER_PATH)
    
    # Auto-Calibrate Clusters (Tiny bytes = Malware)
    centroids = kmeans_scaler.inverse_transform(kmeans_model.cluster_centers_)
    if centroids[0][4] < centroids[1][4]:
        MALWARE_CLUSTER = 0
    else:
        MALWARE_CLUSTER = 1
        
    MODELS_LOADED = True
    logger.info("✅ Production AI Engine Online.")
except Exception as e:
    logger.error(f"❌ AI Engine Offline: {e}")
    MODELS_LOADED = False

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats', methods=['GET'])
def get_stats():
    status = "Online" if MODELS_LOADED else "Offline"
    return jsonify({"model_name": status, "stats": STATS, "logs": RECENT_LOGS})

@app.route('/api/analyze', methods=['POST'])
def analyze_packet():
    global STATS
    
    # 1. SECURITY CHECK (API KEY)
    # C++ must send header: "x-api-key: guardnet-secret-access-token"
    client_key = request.headers.get('x-api-key')
    if client_key != API_KEY:
        logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
        return jsonify({"error": "Unauthorized"}), 401

    if not MODELS_LOADED:
        return jsonify({"error": "AI Engine Offline"}), 503

    try:
        data = request.json
        # 2. ROBUST INPUT HANDLING (Default to 0 if missing)
        features_raw = [
            float(data.get('duration', 0)),
            float(data.get('protocol_type', 0)),
            float(data.get('service', 0)),
            float(data.get('flag', 0)),
            float(data.get('src_bytes', 0)),
            float(data.get('dst_bytes', 0)),
            float(data.get('count', 1)),
            float(data.get('srv_count', 1))
        ]
        
        # --- GATE 1: CLUSTERING ---
        features_k = kmeans_scaler.transform([features_raw])
        distances = kmeans_model.transform(features_k)
        min_dist = np.min(distances)
        nearest = np.argmin(distances)
        
        # --- DECISION LOGIC ---
        source = "Clustering"
        # If distance > 3.0, it's an anomaly -> Ask Deep Learning
        if min_dist > 3.0: 
            source = "Deep Learning"
            features_lstm = lstm_scaler.transform([features_raw])
            features_lstm = np.reshape(features_lstm, (1, 1, 8))
            pred = lstm_model.predict(features_lstm, verbose=0)[0][0]
            status = "Malicious" if pred > 0.5 else "Normal"
            confidence = float(pred)
            STATS["anomalies"] += 1
        else:
            status = "Malicious" if nearest == MALWARE_CLUSTER else "Normal"
            confidence = 1.0 - (min_dist / 5.0)

        # Update Stats & Logs
        if status == "Malicious": STATS["malicious"] += 1
        else: STATS["normal"] += 1
        
        log_entry = {
            "id": data.get('id', 'REALTIME'),
            "time": datetime.now().strftime("%H:%M:%S"),
            "status": status,
            "source": source,
            "confidence": f"{max(0, min(confidence, 1.0)):.2%}",
            "info": f"{int(features_raw[4])}B / Port {int(features_raw[2])}"
        }
        RECENT_LOGS.insert(0, log_entry)
        if len(RECENT_LOGS) > 20: RECENT_LOGS.pop()

        return jsonify({"status": status, "confidence": confidence})

    except Exception as e:
        logger.error(f"Analysis Error: {e}")
        return jsonify({"error": "Invalid Data Format"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)