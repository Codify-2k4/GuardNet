import requests
import time
import random
import sys

# URL of your Dockerized Flask App
API_URL = "http://localhost:5000/api/analyze"

def get_random_packet(profile):
    """Generates a packet based on the specific profile"""
    
    if profile == "MALWARE":
        # --- PROFILE: KNOWN MALWARE ---
        # Matches your uploaded CSV: Tiny size, often 0 destination bytes
        return {
            "id": random.randint(10000, 99999),
            "duration": 0.1,
            "protocol_type": 1,
            "service": 0, # Often 0 in your data
            "flag": 0,
            "src_bytes": random.randint(20, 100),   # TINY (Matches your data)
            "dst_bytes": 0,                         # Matches your data
            "count": 1,
            "srv_count": 1
        }
    
    elif profile == "NORMAL":
        # --- PROFILE: KNOWN NORMAL ---
        # Matches Synthetic Data: Heavy web traffic (Video/Downloads)
        return {
            "id": random.randint(1000, 9999),
            "duration": random.uniform(5, 60),
            "protocol_type": 1,
            "service": 443, # HTTPS
            "flag": 0,
            "src_bytes": random.randint(5000, 40000),  # LARGE
            "dst_bytes": random.randint(5000, 40000),
            "count": random.randint(10, 40),
            "srv_count": random.randint(10, 40)
        }
        
    elif profile == "ANOMALY":
        # --- PROFILE: UNKNOWN / ANOMALY ---
        # Something "In Between" to confuse the Clustering and trigger Deep Learning
        # Example: Medium size, Weird port (IRC/Botnet style)
        return {
            "id": random.randint(50000, 59999),
            "duration": 2.5,
            "protocol_type": 1,
            "service": 6667, # IRC Port (Suspicious but maybe not in training)
            "flag": 0,
            "src_bytes": random.randint(1500, 3000), # Medium (Too big for Malware, Too small for Normal)
            "dst_bytes": random.randint(100, 500),
            "count": 5,
            "srv_count": 5
        }

def start_simulation():
    print(f"--- Starting Hybrid Traffic Simulation ---")
    print(f"Target: {API_URL}")
    print("Press CTRL+C to stop.\n")

    try:
        while True:
            # Randomly pick a scenario
            # 40% Malware, 40% Normal, 20% Anomalies
            rand_val = random.random()
            if rand_val < 0.4:
                profile = "MALWARE"
            elif rand_val < 0.8:
                profile = "NORMAL"
            else:
                profile = "ANOMALY"

            packet = get_random_packet(profile)
            
            try:
                # Send to API
                response = requests.post(API_URL, json=packet)
                
                if response.status_code == 200:
                    res = response.json()
                    
                    # Extract fields (handling older API versions just in case)
                    status = res.get('status', 'Unknown')
                    source = res.get('source', 'Unknown') # 'Clustering' or 'Deep Learning'
                    conf = res.get('confidence', 0)
                    if isinstance(conf, str): conf = float(conf.strip('%')) / 100
                    
                    # Colors for Terminal
                    # Red = Malicious, Green = Normal, Yellow = Deep Learning Intervention
                    if status == "Malicious":
                        color = "\033[91m" # Red
                    else:
                        color = "\033[92m" # Green
                    
                    source_color = "\033[94m" if "Deep" in source else "\033[90m" # Blue or Grey
                    reset = "\033[0m"

                    print(f"[{profile:7}] Size:{packet['src_bytes']:<5} -> {source_color}[{source}]{reset} says: {color}{status}{reset}")
                else:
                    print(f"Error: Server returned {response.status_code}")
                    
            except requests.exceptions.ConnectionError:
                print("Error: Could not connect to GuardNet. Is Docker running?")
                time.sleep(2)
            
            # Rate limit (faster for demo)
            time.sleep(0.8)

    except KeyboardInterrupt:
        print("\nSimulation stopped.")

if __name__ == "__main__":
    start_simulation()