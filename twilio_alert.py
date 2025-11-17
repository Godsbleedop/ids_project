"""
Twilio SMS Alert System
Sends SMS notifications for detected threats
"""

from twilio.rest import Client
from datetime import datetime
import os

class TwilioAlert:
    def __init__(self):
        # Twilio credentials (will be set via config)
        self.account_sid = None
        self.auth_token = None
        self.from_number = None
        self.to_numbers = []
        self.enabled = False
        self.alert_cooldown = {}  # Prevent spam
        self.cooldown_period = 300  # 5 minutes between same alert types
        
    def configure(self, account_sid, auth_token, from_number, to_numbers):
        """
        Configure Twilio credentials
        """
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_number = from_number
        self.to_numbers = to_numbers if isinstance(to_numbers, list) else [to_numbers]
        self.enabled = True
        print("[*] Twilio alerts configured successfully")
    
    def should_send_alert(self, threat_type):
        """
        Check if we should send alert (avoid spam)
        """
        current_time = datetime.now().timestamp()
        last_alert_time = self.alert_cooldown.get(threat_type, 0)
        
        if current_time - last_alert_time > self.cooldown_period:
            self.alert_cooldown[threat_type] = current_time
            return True
        return False
    
    def send_alert(self, threat_type, severity, description, source_ip, details):
        """
        Send SMS alert via Twilio
        """
        if not self.enabled:
            print("[!] Twilio alerts not configured")
            return False
        
        # Check cooldown to prevent spam
        if not self.should_send_alert(threat_type):
            print(f"[*] Alert cooldown active for {threat_type}")
            return False
        
        try:
            client = Client(self.account_sid, self.auth_token)
            
            # Create alert message
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            message_body = f"""
🚨 SECURITY ALERT 🚨

Threat: {threat_type}
Severity: {severity}
Time: {timestamp}

Description: {description}

Source IP: {source_ip}
Protocol: {details.get('protocol', 'unknown')}
Service: {details.get('service', 'unknown')}
Connections: {details.get('connection_count', 0)}

Action Required: Investigate immediately
            """.strip()
            
            # Send to all configured numbers
            for to_number in self.to_numbers:
                message = client.messages.create(
                    body=message_body,
                    from_=self.from_number,
                    to=to_number
                )
                print(f"[✓] Alert sent to {to_number} - SID: {message.sid}")
            
            return True
            
        except Exception as e:
            print(f"[!] Failed to send Twilio alert: {e}")
            return False
    
    def test_alert(self):
        """
        Send test alert to verify configuration
        """
        if not self.enabled:
            return False, "Twilio not configured"
        
        try:
            client = Client(self.account_sid, self.auth_token)
            test_message = f"""
🧪 TEST ALERT
IDS System Online
Time: {datetime.now().strftime('%H:%M:%S')}
This is a test message from your IDS.
            """.strip()
            
            for to_number in self.to_numbers:
                client.messages.create(
                    body=test_message,
                    from_=self.from_number,
                    to=to_number
                )
            
            return True, "Test alert sent successfully"
        except Exception as e:
            return False, f"Error: {str(e)}"
