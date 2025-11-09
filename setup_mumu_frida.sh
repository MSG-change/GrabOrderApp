#!/bin/bash
# MuMu Emulator Frida Setup Script
# This script sets up Frida server for MuMu emulator

echo "🔧 MuMu Emulator Frida Setup"
echo "================================"

# Check ADB connection
echo "📱 Checking ADB connection to MuMu..."
adb connect 127.0.0.1:7555 2>/dev/null || adb connect 127.0.0.1:5555 2>/dev/null

if ! adb devices | grep -q "device$"; then
    echo "❌ No MuMu emulator connected"
    echo "   Please start MuMu emulator and enable USB debugging"
    exit 1
fi

echo "✅ MuMu emulator connected"

# Check architecture
echo "🔍 Checking MuMu architecture..."
ARCH=$(adb shell getprop ro.product.cpu.abi)
echo "   Architecture: $ARCH"

# Determine Frida server version
FRIDA_VERSION="16.1.8"
if [[ "$ARCH" == *"arm64"* ]]; then
    FRIDA_ARCH="arm64"
elif [[ "$ARCH" == *"x86_64"* ]]; then
    FRIDA_ARCH="x86_64"
else
    FRIDA_ARCH="arm"
fi

echo "   Using Frida server for: $FRIDA_ARCH"

# Download Frida server
FRIDA_SERVER="frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}"
FRIDA_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_SERVER}.xz"

if [ ! -f "${FRIDA_SERVER}" ]; then
    echo "📥 Downloading Frida server..."
    curl -L -o "${FRIDA_SERVER}.xz" "$FRIDA_URL"
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to download Frida server"
        exit 1
    fi
    
    echo "📦 Extracting Frida server..."
    unxz "${FRIDA_SERVER}.xz"
    chmod +x "${FRIDA_SERVER}"
fi

# Push Frida server to device
echo "📤 Pushing Frida server to MuMu..."
adb push "${FRIDA_SERVER}" /data/local/tmp/frida-server

# Set permissions
echo "🔐 Setting permissions..."
adb shell "chmod 755 /data/local/tmp/frida-server"

# Check if device is rooted
echo "🔍 Checking root access..."
if adb shell "su -c 'echo root'" 2>/dev/null | grep -q "root"; then
    echo "✅ Root access available"
    
    # Start Frida server
    echo "🚀 Starting Frida server..."
    adb shell "su -c 'killall frida-server 2>/dev/null; /data/local/tmp/frida-server -D &'"
    
    sleep 2
    
    # Verify Frida server is running
    if adb shell "ps" | grep -q "frida-server"; then
        echo "✅ Frida server is running"
    else
        echo "⚠️ Frida server may not be running properly"
    fi
else
    echo "⚠️ Root access not available"
    echo "   Frida server requires root access to function properly"
    echo "   The app will use file-based token monitoring instead"
fi

# Create token file for fallback
echo "📝 Creating token file for fallback mode..."
adb shell "touch /sdcard/grab_order_token.json"
adb shell "chmod 666 /sdcard/grab_order_token.json"

echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Install the Grab Order Assistant APK:"
echo "   adb install bin/GrabOrderAssistant.apk"
echo ""
echo "2. Start the app in MuMu emulator"
echo ""
echo "3. If Frida doesn't work, the app will automatically"
echo "   fall back to file-based token monitoring"
echo ""
echo "4. For file-based mode, run the PC Frida script:"
echo "   python3 frida_grab_order.py"
echo ""
