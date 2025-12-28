import threading
import time
from collections import deque
from src.utils.logger import setup_logger

logger = setup_logger("sentinel_ai")

class SentinelAI:
    def __init__(self):
        self.running = False
        self.threat_buffer = deque(maxlen=100) # Memory of recent attacks
        self.active_threats = []
        
    def start(self):
        """Starts the background monitoring thread"""
        self.running = True
        thread = threading.Thread(target=self._monitor_loop, daemon=True)
        thread.start()
        logger.info("👁️ Sentinel AI (Automation) Started in Background")

    def log_threat(self, packet_data):
        """Called by app.py whenever a 'Malicious' packet is found"""
        # Non-blocking: just add to queue and return
        self.threat_buffer.append({
            "time": time.time(),
            "info": packet_data
        })

    def _monitor_loop(self):
        """The brain that watches for patterns 24/7"""
        while self.running:
            try:
                self._analyze_patterns()
                time.sleep(2) # Check every 2 seconds
            except Exception as e:
                logger.error(f"Sentinel Error: {e}")

    def _analyze_patterns(self):
        # 1. Clean old data (older than 10 seconds)
        current_time = time.time()
        recent_attacks = [x for x in self.threat_buffer if current_time - x['time'] < 10]
        
        # 2. Heuristic Logic (The "AI" Automation)
        # If we see > 5 attacks in 10 seconds, it's a FLOOD Attack
        if len(recent_attacks) > 5:
            self._trigger_response("High Velocity Attack Detected (Potential DDoS)")
            self.threat_buffer.clear() # Reset to avoid spamming alerts

    def _trigger_response(self, threat_name):
        """AUTOMATION ACTION: This is where you put your response logic"""
        logger.warning(f"🚨 AUTOMATION TRIGGERED: {threat_name}")
        
        # Example Automations:
        # 1. Write to a special 'Banned IPs' file for the Firewall
        with open("banned_ips.log", "a") as f:
            f.write(f"{time.ctime()} - BLOCK TRIGGERED BY SENTINEL\n")
            
        # 2. (Optional) Send Email / Discord Webhook
        # requests.post("discord_webhook_url", json={"content": "Under Attack!"})
        
        print(f"\n[SENTINEL] 🛡️ countermeasures deployed against: {threat_name}\n")

# Global Instance
sentinel = SentinelAI()