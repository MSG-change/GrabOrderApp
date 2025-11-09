# Deployment Guide - Grab Order Assistant v1.3.0

## Build Status
- **Version**: 1.3.0
- **Build System**: GitHub Actions + Buildozer
- **Target**: Android (ARM64 + ARMv7)

## Download APK

1. Go to: https://github.com/MSG-change/GrabOrderApp/actions
2. Click on the latest successful workflow run
3. Download the `graborder-apk` artifact
4. Extract the APK file

## Installation on MuMu Emulator

### Step 1: Install APK
```bash
# Connect to MuMu emulator
adb connect 127.0.0.1:7555

# Install APK
adb install -r graborder-*.apk
```

### Step 2: Setup Frida Server (for MuMu)
```bash
cd GrabOrderApp
./setup_mumu_frida.sh
```

This script will:
- Detect MuMu architecture
- Download correct Frida server
- Install and start Frida server on MuMu
- Test connectivity

### Step 3: Launch App
1. Open the app on MuMu emulator
2. Click "Start" button
3. The app will use MuMuFridaService to connect to external Frida server
4. Token will be captured automatically

## Installation on Real Device

### Step 1: Install APK
```bash
# Connect device via USB
adb devices

# Install APK
adb install -r graborder-*.apk
```

### Step 2: Launch App
1. Open the app on device
2. Click "Start" button
3. The app will use FridaAPKService (internal Frida)
4. Token will be captured automatically

## Troubleshooting

### MuMu Emulator Issues

**Problem**: Frida server not running
```bash
# Check if Frida server is running
adb shell ps | grep frida

# Restart Frida server
./setup_mumu_frida.sh
```

**Problem**: App can't connect to Frida
```bash
# Check logs
adb logcat | grep Frida
```

### Real Device Issues

**Problem**: Permission denied
- Grant all requested permissions in Android settings
- Enable "Install from unknown sources"

**Problem**: App crashes on startup
```bash
# Check crash logs
adb logcat | grep graborder
```

## Architecture Overview

### Service Selection Logic

```
MuMu Emulator:
  1. Try MuMuFridaService (external Frida server)
  2. Fallback to FridaAPKService
  3. Fallback to FridaTokenServiceSimple (file monitoring)

Real Device:
  1. Try FridaAPKService (internal Frida)
  2. Fallback to FridaManager
  3. Fallback to FridaTokenServiceSimple
```

### Key Features

- **Smart Environment Detection**: Automatically detects MuMu vs real device
- **Automatic Fallback**: Multiple service layers for reliability
- **External Frida Support**: MuMu uses external Frida server to avoid architecture conflicts
- **Token Management**: Automatic token capture and storage

## Version History

### v1.3.0 (Current)
- Simplified buildozer.spec based on official best practices
- Removed all problematic configurations
- Stable Kivy 2.3.0 build
- Clean GitHub Actions workflow

### v1.2.x
- Multiple attempts to fix Kivy compilation issues
- Added MuMu Frida support
- Converted all Chinese to English

## Support

For issues or questions:
1. Check GitHub Actions build logs
2. Review MuMu Frida setup script output
3. Check app logs with `adb logcat`
