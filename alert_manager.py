import time
import json
import os
import requests
from datetime import datetime

class AlertManager:
    def __init__(self, config_file="alert_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        self.last_alert_time = 0
        self.alert_count = 0
        
    def load_config(self):
        """Load alert configuration from file"""
        default_config = {
            "enabled": False,
            "cooldown_seconds": 60,
            "telegram_bot_token": "",
            "telegram_chat_id": ""
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded = json.load(f)
                    default_config.update(loaded)
            except Exception as e:
                print(f"[!] Error loading config: {e}")
        
        return default_config
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"[!] Error saving config: {e}")
            return False
    
    def update_config(self, new_config):
        """Update configuration"""
        self.config.update(new_config)
        return self.save_config()
    
    def can_send_alert(self):
        """Check if enough time has passed since last alert (rate limiting)"""
        current_time = time.time()
        cooldown = self.config.get("cooldown_seconds", 60)
        
        if current_time - self.last_alert_time >= cooldown:
            return True
        return False
    
    def send_alert(self, threat_info):
        """Send alert through Telegram"""
        if not self.config.get("enabled", False):
            return {"status": "disabled", "message": "Alerts are disabled"}
        
        if not self.can_send_alert():
            time_left = int(self.config["cooldown_seconds"] - (time.time() - self.last_alert_time))
            return {"status": "cooldown", "message": f"Cooldown active. Wait {time_left}s"}
        
        try:
            result = self.send_telegram(threat_info)
            
            if result.get("status") == "success":
                self.last_alert_time = time.time()
                self.alert_count += 1
            
            return result
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def send_telegram(self, threat_info):
        """Send alert via Telegram Bot"""
        try:
            bot_token = self.config.get("telegram_bot_token")
            chat_id = self.config.get("telegram_chat_id")
            
            if not bot_token or not chat_id:
                return {"status": "error", "message": "Telegram credentials not configured"}
            
            message_text = f"""
🚨 *IDS ALERT* 🚨

*Threat:* {threat_info.get('type', 'Unknown')}
*Source:* `{threat_info.get('src', 'Unknown')}`
*Destination:* `{threat_info.get('dst', 'Unknown')}`
*Protocol:* {threat_info.get('proto', 'Unknown')}
*Confidence:* {threat_info.get('confidence', 0):.0%}
*Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """.strip()
            
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": message_text,
                "parse_mode": "Markdown"
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                return {"status": "success", "message": "Telegram alert sent"}
            else:
                error_msg = response.json().get('description', 'Unknown error')
                return {"status": "error", "message": f"Telegram API error: {error_msg}"}
            
        except requests.exceptions.RequestException as e:
            return {"status": "error", "message": f"Network error: {str(e)}"}
        except Exception as e:
            return {"status": "error", "message": f"Failed to send: {str(e)}"}
    
    def send_test_alert(self):
        """Send a test alert"""
        test_threat = {
            "type": "Test Alert",
            "src": "192.168.1.100",
            "dst": "192.168.100.10",
            "proto": "TCP",
            "confidence": 0.95
        }
        
        # Temporarily bypass cooldown and enabled check for manual test
        original_cooldown = self.config["cooldown_seconds"]
        original_enabled = self.config.get("enabled", False)
        
        self.config["cooldown_seconds"] = 0
        self.config["enabled"] = True
        
        result = self.send_alert(test_threat)
        
        # Restore original settings
        self.config["cooldown_seconds"] = original_cooldown
        self.config["enabled"] = original_enabled
        
        return result
