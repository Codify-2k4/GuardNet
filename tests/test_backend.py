import requests
import pytest

# CONFIGURATION
BASE_URL = "http://localhost:5000"
API_KEY = "guardnet-secret-access-token"

# HEADERS (Correct & Incorrect)
HEADERS_VALID = {"x-api-key": API_KEY, "Content-Type": "application/json"}
HEADERS_INVALID = {"x-api-key": "wrong-password", "Content-Type": "application/json"}

def test_server_is_online():
    """Check if the dashboard/stats endpoint works"""
    try:
        response = requests.get(f"{BASE_URL}/api/stats")
        assert response.status_code == 200
        json_data = response.json()
        assert "model_name" in json_data
        print("\n✅ Server is Online")
    except requests.exceptions.ConnectionError:
        pytest.fail("❌ Server is DOWN. Is Docker running?")

def test_security_rejects_strangers():
    """Ensure unauthorized requests are blocked"""
    packet = {"src_bytes": 100}
    
    # 1. No Key
    resp1 = requests.post(f"{BASE_URL}/api/analyze", json=packet)
    assert resp1.status_code == 401
    
    # 2. Wrong Key
    resp2 = requests.post(f"{BASE_URL}/api/analyze", json=packet, headers=HEADERS_INVALID)
    assert resp2.status_code == 401
    print("✅ Security System (API Key) is working")

def test_detect_malware():
    """Send a 'Tiny' packet and verify it is detected as Malicious"""
    malware_packet = {
        "src_bytes": 50,  # Tiny bytes (from your training data)
        "service": 0,
        "protocol_type": 1,
        "count": 1
    }
    response = requests.post(f"{BASE_URL}/api/analyze", json=malware_packet, headers=HEADERS_VALID)
    assert response.status_code == 200
    assert response.json()['status'] == "Malicious"
    print("✅ Malware Detection Logic is working")

def test_detect_normal():
    """Send a 'Heavy' packet and verify it is detected as Normal"""
    # We must provide ALL fields to match the 'Normal' profile
    # Normal traffic usually has return traffic (dst_bytes) and takes time (duration)
    normal_packet = {
        "src_bytes": 20000, 
        "dst_bytes": 20000,  # Added: Normal traffic downloads data too
        "service": 443,
        "protocol_type": 1,
        "duration": 5.0,     # Added: Normal sessions last longer
        "count": 20,
        "srv_count": 20,     # Added: Consistent with Normal profile
        "flag": 0
    }
    
    response = requests.post(f"{BASE_URL}/api/analyze", json=normal_packet, headers=HEADERS_VALID)
    
    # Debugging: Print what happened if it fails
    if response.json()['status'] != "Normal":
        print(f"\nAI Response: {response.json()}")

    assert response.status_code == 200
    assert response.json()['status'] == "Normal"
    print("✅ Normal Traffic Logic is working")

def test_robustness_incomplete_data():
    """Send incomplete JSON and ensure server doesn't crash"""
    broken_packet = {"src_bytes": 500} # Missing other fields
    
    response = requests.post(f"{BASE_URL}/api/analyze", json=broken_packet, headers=HEADERS_VALID)
    
    # Your robust backend should handle this (either 200 with defaults or 400)
    # Our optimized code defaults to 0, so it should be 200 OK.
    assert response.status_code == 200 
    print("✅ Robustness Check Passed (No Crash on bad data)")