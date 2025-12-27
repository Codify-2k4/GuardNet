import requests
import time
import concurrent.futures

API_URL = "http://localhost:5000/api/analyze"
API_KEY = "guardnet-secret-access-token"
HEADERS = {"x-api-key": API_KEY}
TOTAL_REQUESTS = 1000
CONCURRENT_USERS = 50  # Simulating 50 threads sending data at once

packet = {
    "src_bytes": 1200, 
    "service": 80, 
    "protocol_type": 1,
    "count": 5
}

def send_request(i):
    try:
        start = time.time()
        resp = requests.post(API_URL, json=packet, headers=HEADERS, timeout=5)
        latency = time.time() - start
        return resp.status_code, latency
    except Exception as e:
        return "Error", 0

print(f"--- STARTING STRESS TEST: {TOTAL_REQUESTS} Packets ---")
start_time = time.time()

success_count = 0
error_count = 0
latencies = []

# Use ThreadPool to blast the server
with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_USERS) as executor:
    futures = [executor.submit(send_request, i) for i in range(TOTAL_REQUESTS)]
    
    for future in concurrent.futures.as_completed(futures):
        status, latency = future.result()
        if status == 200:
            success_count += 1
            latencies.append(latency)
        else:
            error_count += 1

total_time = time.time() - start_time
avg_latency = sum(latencies) / len(latencies) if latencies else 0

print("\n--- RESULTS ---")
print(f"Time Taken:      {total_time:.2f} seconds")
print(f"Requests/Sec:    {TOTAL_REQUESTS / total_time:.2f} RPS")
print(f"Successful:      {success_count}")
print(f"Failed:          {error_count}")
print(f"Avg Response:    {avg_latency * 1000:.2f} ms")

if error_count == 0 and avg_latency < 0.1:
    print("✅ PERFORMANCE: EXCELLENT")
elif error_count == 0:
    print("✅ PERFORMANCE: GOOD")
else:
    print("❌ PERFORMANCE: FAILED (Server dropped packets)")