# Voice Notification & Multi-Area Guide

## 🔊 Voice Notification Feature

### What it does
When you successfully grab an order, the app will play a voice alert saying:
**"抢单成功，快来看看"** (Order grabbed successfully, come and check!)

### How it works

#### On Android (Primary method)
- Uses Android's built-in TTS (Text-to-Speech)
- Automatically speaks in Chinese
- No additional setup required
- Works out of the box

#### On PC (Alternative methods)
1. **pyttsx3 TTS** (Text-to-Speech)
   ```bash
   pip install pyttsx3
   ```

2. **pygame Audio** (Fallback - plays audio file)
   ```bash
   pip install pygame
   ```
   
   Place an audio file named `success.mp3` in:
   - `GrabOrderApp/resources/success.mp3`, or
   - `GrabOrderApp/success.mp3`

### How to use

1. **Enable/Disable in UI**
   - Find the "Voice Alert" checkbox in the main interface
   - ✅ Checked = Enabled (default)
   - ☐ Unchecked = Disabled

2. **The voice will play automatically** when:
   - An order is successfully grabbed
   - HTTP response code is 200 or 0
   - Runs in background (non-blocking)

### Configuration

```python
# In config or UI
enable_voice_notification = True  # or False
```

### Troubleshooting

**No sound on Android?**
- Check device volume
- Grant TTS permissions
- Check logs for "[VOICE]" messages

**No sound on PC?**
- Install pyttsx3: `pip install pyttsx3`
- Or install pygame: `pip install pygame`
- Provide `success.mp3` audio file

**Check logs:**
```
[VOICE] Android TTS initialized          ✅ Working
[VOICE] PC TTS (pyttsx3) initialized     ✅ Working
[VOICE] Audio player (pygame) initialized ✅ Working
[VOICE] Voice notification not available  ❌ Not working
```

---

## 🌍 Multi-Area Order Support

### What it does
Allows you to monitor and grab orders from specific server areas only, instead of all areas.

### API Parameters

The app uses this API endpoint:
```
GET /gate/app-api/club/order/getOrderPoolsList
  ?productCategoryParentId=2469
  &userServerAreaId=823
```

**Parameters:**
- `productCategoryParentId`: Category ID (e.g., 2469)
- `userServerAreaId`: Server area ID
  - **Empty** = All areas (default)
  - **823** = Area 823 only
  - **824** = Area 824 only
  - etc.

### How to use

1. **In the UI:**
   - Find the "Area ID" input field
   - Leave **empty** for all areas (default)
   - Enter specific ID (e.g., `823`) for that area only

2. **Examples:**
   ```
   Area ID: ""     → All areas
   Area ID: "823"  → Only area 823
   Area ID: "824"  → Only area 824
   ```

3. **The app will:**
   - Only fetch orders from the specified area
   - Show area ID in startup log
   - Use the configured area for all requests

### Configuration

```python
# In config or UI
user_server_area_id = ''     # All areas
user_server_area_id = '823'  # Area 823 only
user_server_area_id = '824'  # Area 824 only
```

### Logs

When starting, you'll see:
```
[CONFIG] Category ID: 131
[CONFIG] Server Area ID: 823           ← Specific area
```

Or:
```
[CONFIG] Category ID: 131
[CONFIG] Server Area ID: All areas     ← All areas
```

---

## 📱 UI Components

### New UI Elements

1. **Area ID Input**
   - Label: "Area ID"
   - Hint: "Server Area ID (empty=all)"
   - Default: Empty (all areas)

2. **Voice Alert Checkbox**
   - Label: "Voice Alert"
   - Default: ✅ Checked (enabled)

### Screenshot Reference

```
┌─────────────────────────────────┐
│ Token:    [__________________ ] │
│ Club ID:  [27________________ ] │
│ Role ID:  [317_______________ ] │
│ Tenant:   [212_______________ ] │
│ Category: [131_______________ ] │
│ Area ID:  [__________________ ] │ ← NEW
│ Voice:    [✓]                   │ ← NEW
│                                 │
│  [Start]         [Stop]         │
└─────────────────────────────────┘
```

---

## 🎵 Creating Custom Success Sound

### For PC/pygame users:

1. Record your own message
2. Convert to MP3 format
3. Name it `success.mp3`
4. Place in `GrabOrderApp/resources/success.mp3`

### Recommended settings:
- Format: MP3
- Duration: 2-3 seconds
- Bit rate: 128 kbps
- Sample rate: 44100 Hz

### Example messages:
- "抢单成功，快来看看"
- "订单已抢到"
- "Success!"
- Custom chime/beep sound

---

## 🔧 Advanced Configuration

### Disable voice programmatically

```python
# In fast_grab_service.py
self.enable_voice = False
```

### Change TTS settings (PC)

```python
# In _init_voice_notification()
self.tts_engine.setProperty('rate', 150)    # Speed (default 150)
self.tts_engine.setProperty('volume', 1.0)  # Volume (0.0 to 1.0)
```

### Change voice message

```python
# In _play_success_sound_async()
message = "Your custom message here"
```

---

## 📊 Testing

### Test voice notification:

1. Start the app with voice enabled
2. Wait for an order
3. Successfully grab it
4. You should hear the voice alert

### Test multi-area:

1. Set Area ID to specific value (e.g., 823)
2. Check logs for: `[CONFIG] Server Area ID: 823`
3. Verify API requests include `userServerAreaId=823`

### Check logs:

```
[VOICE] Android TTS initialized
[CONFIG] Server Area ID: 823
[SUCCESS] ✅ Order grabbed successfully!
[VOICE] Playing success notification (Android TTS)
```

---

## 🎯 Best Practices

1. **Voice notification:**
   - Keep device volume reasonable
   - Test before going live
   - Disable if in quiet environment

2. **Multi-area:**
   - Leave empty if monitoring all areas
   - Use specific ID only if needed
   - Confirm correct area ID before starting

3. **Performance:**
   - Voice runs in background (won't slow down grabbing)
   - Multi-area filters on server side (efficient)

---

## 📝 Version History

- **v1.8.0**: Added voice notification and multi-area support
- **v1.7.3**: Instant grab mode logging fixes
- **v1.7.0**: Geetest optimization improvements

---

## 💡 Tips

1. **Can't find your area ID?**
   - Check the API logs
   - Look for `userServerAreaId` in requests
   - Ask your admin for area IDs

2. **Want different notification sound?**
   - Replace `success.mp3` with your own
   - Keep it short (2-3 seconds)
   - Test volume before live use

3. **Multiple devices?**
   - Each device can monitor different areas
   - Configure area ID per device
   - Coordinate with team

---

## 🆘 Support

If you encounter issues:

1. Check logs for `[VOICE]` and `[CONFIG]` messages
2. Verify permissions (Android TTS, audio playback)
3. Test with voice checkbox enabled/disabled
4. Confirm area ID is correct

Happy grabbing! 🎉
