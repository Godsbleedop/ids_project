"""
Configuration file for IDS system
IMPORTANT: Add this file to .gitignore to protect credentials
"""

# Twilio Configuration
TWILIO_ACCOUNT_SID = ''
TWILIO_AUTH_TOKEN = ''
TWILIO_FROM_NUMBER = ''  # Your Twilio phone number
TWILIO_TO_NUMBERS = ['']  # Phone numbers to receive alerts

# Alert Settings
ALERT_ENABLED = True
ALERT_SEVERITY_THRESHOLD = 'MEDIUM'  # Send alerts for MEDIUM, HIGH, CRITICAL
ALERT_COOLDOWN = 300  # Seconds between same alert types (5 minutes)
