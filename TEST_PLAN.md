# Test Plan - Grab Order Assistant v1.3.0

## Pre-Test Checklist

- [ ] APK downloaded from GitHub Actions
- [ ] MuMu emulator running
- [ ] ADB connected to MuMu (127.0.0.1:7555)
- [ ] Target app (com.dys.shzs) installed on MuMu

## Test 1: MuMu Emulator - External Frida

### Setup
```bash
# 1. Setup Frida server
cd GrabOrderApp
./setup_mumu_frida.sh

# 2. Install app
adb install -r graborder-1.3.0.apk

# 3. Launch app
adb shell am start -n com.graborder/.MainActivity
```

### Expected Behavior
1. App detects MuMu environment
2. Selects MuMuFridaService
3. Connects to external Frida server (127.0.0.1:27042)
4. Hooks target app (com.dys.shzs)
5. Captures token from network requests
6. Displays token in UI

### Verification
```bash
# Check Frida server is running
adb shell ps | grep frida

# Check app logs
adb logcat | grep -E "Frida|Token|MuMu"
```

### Success Criteria
- [ ] Frida server running
- [ ] App connects successfully
- [ ] Token captured and displayed
- [ ] No crashes or errors

## Test 2: Real Device - Internal Frida

### Setup
```bash
# 1. Install app on real device
adb install -r graborder-1.3.0.apk

# 2. Launch app
adb shell am start -n com.graborder/.MainActivity
```

### Expected Behavior
1. App detects real device environment
2. Selects FridaAPKService
3. Uses internal Frida library
4. Hooks target app
5. Captures token
6. Displays token in UI

### Verification
```bash
# Check app logs
adb logcat | grep -E "Frida|Token"
```

### Success Criteria
- [ ] Internal Frida loads successfully
- [ ] Token captured and displayed
- [ ] No architecture conflicts
- [ ] No crashes

## Test 3: Fallback Mechanism

### Test 3a: MuMu without Frida Server

**Setup**: Don't run setup_mumu_frida.sh

**Expected**: App falls back to FridaAPKService or file monitoring

**Verification**:
```bash
adb logcat | grep "Fallback"
```

### Test 3b: File Monitoring Mode

**Setup**: Run PC-side Frida script
```bash
python frida_mumu_helper.py
```

**Expected**: App reads token from /sdcard/grab_order_token.json

**Verification**:
```bash
adb shell cat /sdcard/grab_order_token.json
```

## Test 4: Performance & Stability

### Long-Running Test
1. Start app
2. Let it run for 30 minutes
3. Monitor memory usage
4. Check for crashes

### Verification
```bash
# Memory usage
adb shell dumpsys meminfo com.graborder

# Check if still running
adb shell ps | grep graborder
```

### Success Criteria
- [ ] No memory leaks
- [ ] No crashes
- [ ] Continuous token updates
- [ ] Stable Frida connection

## Test 5: Order Grabbing

### Setup
1. Ensure token is captured
2. Configure order parameters
3. Click "Start Grabbing"

### Expected Behavior
1. App uses captured token
2. Sends order grab requests
3. Displays success/failure
4. Updates UI with results

### Success Criteria
- [ ] Requests sent with correct token
- [ ] API responses received
- [ ] UI updates correctly
- [ ] No authentication errors

## Bug Report Template

If any test fails, use this template:

```
## Bug Report

**Test**: [Test name]
**Environment**: [MuMu/Real Device]
**Version**: 1.3.0

**Steps to Reproduce**:
1. 
2. 
3. 

**Expected Behavior**:


**Actual Behavior**:


**Logs**:
```
[Paste relevant logs here]
```

**Screenshots**:
[If applicable]
```

## Post-Test Actions

### If All Tests Pass
- [ ] Tag release v1.3.0
- [ ] Update documentation
- [ ] Create release notes

### If Tests Fail
- [ ] Collect logs
- [ ] Create bug report
- [ ] Fix issues
- [ ] Increment version
- [ ] Re-test
