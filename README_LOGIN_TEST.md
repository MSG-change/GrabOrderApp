# 📱 Login Test App

Test Geetest verification during login process.

## ✨ Features

- ✅ English UI (no Chinese encoding issues)
- ✅ Geetest verification integration
- ✅ Remote AI recognition
- ✅ SMS code sending
- ✅ Login with SMS code
- ✅ Real-time logging

## 🚀 Quick Start

### Option 1: Local Test (Recommended)

```bash
# Run the launcher script
./run_login_test.sh
```

### Option 2: Manual Run

```bash
# Set AI server URL
export AI_SERVER_URL=http://127.0.0.1:8889

# Run test app
python3 test_login_ui.py
```

### Option 3: Build APK for Phone

```bash
# Build APK
buildozer -v android debug

# Install to phone
adb install -r bin/logintest-1.0.0-arm64-v8a-debug.apk
```

## 📋 Test Steps

### Step 1: Send SMS Code

1. Enter phone number (default: 18113011654)
2. Click "Send Code" button
3. Wait for Geetest verification
4. Check phone for SMS code

**What happens:**
```
User clicks "Send Code"
    ↓
Generate challenge (based on phone + timestamp)
    ↓
Geetest Load (get lot_number, imgs, ques)
    ↓
AI Recognition (get answers: [2, 5, 7])
    ↓
Generate W parameter
    ↓
Geetest Verify (get pass_token)
    ↓
Send SMS code with geeDto
    ↓
✅ SMS sent!
```

### Step 2: Login

1. Enter SMS code from phone
2. Click "Login" button
3. Wait for login response
4. Check for success message

**What happens:**
```
User clicks "Login"
    ↓
POST /login with mobile + code
    ↓
Get token from response
    ↓
Save token to file
    ↓
✅ Login successful!
```

## 📊 UI Layout

```
┌─────────────────────────────────────┐
│     Login Test with Geetest         │
├─────────────────────────────────────┤
│ Phone:    [18113011654            ] │
│ SMS Code: [                       ] │
├─────────────────────────────────────┤
│  [Send Code]      [Login]           │
├─────────────────────────────────────┤
│ Log:                                │
│ ┌─────────────────────────────────┐ │
│ │ [10:20:30] Ready...             │ │
│ │ [10:20:35] Sending SMS code...  │ │
│ │ [10:20:36] Geetest success!     │ │
│ │ [10:20:37] SMS sent!            │ │
│ │ [10:21:00] Logging in...        │ │
│ │ [10:21:01] Login successful!    │ │
│ └─────────────────────────────────┘ │
└─────────────────────────────────────┘
```

## 🔍 Log Examples

### Successful Flow

```
[10:20:30] Initializing Geetest helper...
[10:20:31] AI Server: http://127.0.0.1:8889
[10:20:31] Geetest helper initialized
[10:20:31] Ready to test!
[10:20:35] ==================================================
[10:20:35] Step 1: Sending SMS code...
[10:20:35] Performing Geetest verification...
[10:20:35] Challenge: send_18113011654_1762712400...
[10:20:36] Answers: [2, 5, 7]
[10:20:36] Geetest verification success!
[10:20:36] Sending SMS code...
[10:20:37] Response: HTTP 200
[10:20:37] SUCCESS: SMS code sent!
[10:21:00] ==================================================
[10:21:00] Step 2: Logging in...
[10:21:01] Response: HTTP 200
[10:21:01] SUCCESS: Login successful!
[10:21:01] Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
[10:21:01] Saved: login_token_1762712461.txt
```

## 🔧 Configuration

### API Endpoints

- **Base URL**: `https://dysh.dyswl.com`
- **Send Code**: `/gate/app-api/club/auth/sendLoginCode`
- **Login**: `/gate/app-api/club/auth/login`

### Geetest Parameters

- **captcha_id**: `045e2c229998a88721e32a763bc0f7b8`
- **captchaKeyType**: `dlVerify`

### AI Server

- **URL**: `http://127.0.0.1:8889` (local)
- **Health Check**: `/health`
- **Recognition**: `/api/v1/recognize`

## 🐛 Troubleshooting

### AI Server Not Running

```
Error: Connection refused
```

**Solution:**
```bash
cd ../geetest_ai
python3 api_server.py
```

### Geetest Verification Failed

```
Error: Geetest verification failed
```

**Check:**
- AI server is running
- Network connection is OK
- Model file exists

### SMS Not Received

```
SUCCESS: SMS code sent!
(but no SMS received)
```

**Check:**
- Phone number is correct
- Phone has signal
- SMS service is working

### Login Failed

```
Error: 验证码错误
```

**Check:**
- SMS code is correct
- SMS code not expired (usually 5 minutes)
- Entered code matches received code

## 📁 Files

```
GrabOrderApp/
├── test_login_ui.py              # Main test app
├── buildozer_login_test.spec     # Build config
├── run_login_test.sh             # Launcher script
├── LOGIN_TEST_GUIDE.md           # Detailed guide
├── README_LOGIN_TEST.md          # This file
└── libs/
    └── geetest_helper_local.py   # Geetest helper
```

## ✅ Success Criteria

- [x] UI displays correctly (English only)
- [x] No Chinese character issues
- [x] Geetest verification works
- [x] AI recognition accurate
- [x] SMS code sent successfully
- [x] Login successful
- [x] Token saved to file
- [x] Logs are clear and readable

## 🎯 Next Steps

If this test is successful, the same logic can be applied to:
1. Order grabbing flow
2. Other verification scenarios
3. Production deployment

## 📝 Notes

- **UI Language**: English only to avoid encoding issues
- **AI Server**: Must be running before starting app
- **Phone Number**: Default is 18113011654, change as needed
- **Token Storage**: Saved to `login_token_<timestamp>.txt`

## 🚀 Build for Phone

```bash
# Build APK
buildozer -v android debug

# Install
adb install -r bin/logintest-1.0.0-arm64-v8a-debug.apk

# View logs
adb logcat | grep python
```

## 📞 Support

If you encounter issues:
1. Check AI server is running
2. Check network connection
3. Review logs for errors
4. Verify phone number is correct
5. Check SMS service is working
