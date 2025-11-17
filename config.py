"""
Configuration file for IDS system
IMPORTANT: Add this file to .gitignore to protect credentials
"""

# Twilio Configuration
TWILIO_ACCOUNT_SID = 'ACac2a091649a4522654503f87d8633dc6'
TWILIO_AUTH_TOKEN = 'c39cc2aac7ef8fa4ee9e1f50b3fbb67a'
TWILIO_FROM_NUMBER = '+15103913571'  # Your Twilio phone number
TWILIO_TO_NUMBERS = ['+919972576234']  # Phone numbers to receive alerts

# Alert Settings
ALERT_ENABLED = True
ALERT_SEVERITY_THRESHOLD = 'MEDIUM'  # Send alerts for MEDIUM, HIGH, CRITICAL
ALERT_COOLDOWN = 300  # Seconds between same alert types (5 minutes)
