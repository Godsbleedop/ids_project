# 📱 Telegram Alert Setup Guide

## ✅ Why Telegram Instead of Twilio?

- **100% FREE** - No costs, no credits needed
- **Super Easy** - 5 minute setup
- **No Phone Verification** - Just need a Telegram account
- **Instant Notifications** - Faster than SMS
- **Rich Formatting** - Supports markdown, emojis, etc.

---

## 🚀 Quick Setup (5 Minutes)

### Step 1: Create a Telegram Bot

1. Open Telegram app on your phone or desktop
2. Search for **@BotFather** (official Telegram bot)
3. Start a chat and send: `/newbot`
4. Follow the prompts:
   - Give your bot a name (e.g., "IDS Alert Bot")
   - Give it a username (must end in 'bot', e.g., "myids_alert_bot")
5. **BotFather will give you a TOKEN** - it looks like this:
   ```
   123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567890
   ```
6. **COPY THIS TOKEN** - you'll need it!

### Step 2: Get Your Chat ID

1. Search for your bot in Telegram (the username you just created)
2. Click **START** or send any message to your bot
3. Open this URL in your browser (replace YOUR_BOT_TOKEN):
   ```
   https://api.telegram.org/botYOUR_BOT_TOKEN/getUpdates
   ```
   Example:
   ```
   https://api.telegram.org/bot123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567890/getUpdates
   ```
4. You'll see JSON response. Look for `"chat":{"id":` - the number after it is your **CHAT_ID**
   ```json
   "chat": {
     "id": 987654321,  <-- THIS IS YOUR CHAT_ID
     "first_name": "Your Name",
     ...
   }
   ```

### Step 3: Configure Your IDS

Edit the file: `/home/aaron/ids_project/alert_config.json`

```json
{
  "enabled": true,
  "cooldown_seconds": 60,
  "telegram_bot_token": "123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567890",
  "telegram_chat_id": "987654321"
}
```

**Replace:**
- `telegram_bot_token` with your bot token from Step 1
- `telegram_chat_id` with your chat ID from Step 2

### Step 4: Test It!

1. Start your IDS dashboard:
   ```bash
   cd /home/aaron/ids_project
   python app.py
   ```

2. Open the dashboard: http://localhost:5000

3. Click the **"Send Alert"** button

4. You should receive a Telegram message! 🎉

---

## 📋 Example Alert Message

When you click "Send Alert" or when a threat is detected, you'll receive:

```
🚨 IDS ALERT 🚨

Threat: Test Alert
Source: 192.168.1.100
Destination: 192.168.100.10
Protocol: TCP
Confidence: 95%
Time: 2025-11-28 21:52:36
```

---

## 🔧 Configuration Options

### `alert_config.json` Fields:

| Field | Description | Example |
|-------|-------------|---------|
| `enabled` | Enable/disable alerts | `true` or `false` |
| `cooldown_seconds` | Minimum seconds between alerts | `60` (1 minute) |
| `telegram_bot_token` | Your bot token from BotFather | `"123456789:ABC..."` |
| `telegram_chat_id` | Your Telegram chat ID | `"987654321"` |

---

## 🐛 Troubleshooting

### "Telegram credentials not configured"
- Make sure you filled in both `telegram_bot_token` and `telegram_chat_id`
- Check for typos in the config file

### "Network error"
- Check your internet connection
- Make sure the bot token is correct

### "Telegram API error: Unauthorized"
- Your bot token is wrong
- Go back to @BotFather and get the correct token

### "Telegram API error: Bad Request: chat not found"
- Your chat ID is wrong
- Make sure you sent a message to your bot first
- Double-check the chat ID from the getUpdates URL

### Not receiving messages?
1. Make sure you clicked **START** in your bot chat
2. Verify the chat ID is correct (should be a number)
3. Test the bot manually:
   ```bash
   curl -X POST "https://api.telegram.org/botYOUR_BOT_TOKEN/sendMessage" \
        -H "Content-Type: application/json" \
        -d '{"chat_id": "YOUR_CHAT_ID", "text": "Test message"}'
   ```

---

## 🎯 Quick Test Command

Test your Telegram setup directly:

```bash
cd /home/aaron/ids_project
python -c "
from alert_manager import AlertManager
am = AlertManager()
result = am.send_test_alert()
print(result)
"
```

If successful, you'll see:
```
{'status': 'success', 'message': 'Telegram alert sent'}
```

---

## 📝 Files Modified

- ✅ `/home/aaron/ids_project/alert_manager.py` - Replaced Twilio with Telegram
- ✅ `/home/aaron/ids_project/alert_config.json` - Updated config format

---

## 💡 Pro Tips

1. **Group Alerts**: You can add the bot to a Telegram group and use the group's chat ID to send alerts to multiple people!

2. **Multiple Bots**: Create different bots for different severity levels

3. **Custom Messages**: Edit `alert_manager.py` line 88-95 to customize the alert format

4. **No Dependencies**: Uses only the `requests` library (already installed with Flask)

---

## ✨ That's It!

You now have a **FREE, EASY, and RELIABLE** alert system! 🎉

No more Twilio issues, no phone verification, no costs!
