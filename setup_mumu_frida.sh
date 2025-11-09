#!/bin/bash
# MuMu Emulator Frida Setup Script - Enhanced Version
# This script sets up Frida server for MuMu emulator with proper architecture handling

echo "🔧 MuMu Emulator Frida Setup (Enhanced)"
echo "========================================"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check ADB connection
echo "📱 Connecting to MuMu emulator..."

# Try multiple MuMu ports
CONNECTED=false
for PORT in 7555 5555 16384 21503; do
    echo "   Trying port $PORT..."
    if adb connect 127.0.0.1:$PORT 2>&1 | grep -q "connected"; then
        CONNECTED=true
        echo -e "${GREEN}✅ Connected on port $PORT${NC}"
        break
    fi
done

if [ "$CONNECTED" = false ]; then
    echo -e "${RED}❌ Failed to connect to MuMu emulator${NC}"
    echo "   Please ensure:"
    echo "   1. MuMu emulator is running"
    echo "   2. USB debugging is enabled"
    exit 1
fi

# Check architecture
echo ""
echo "🔍 Detecting MuMu architecture..."
ARCH=$(adb shell getprop ro.product.cpu.abi)
echo "   Raw architecture: $ARCH"

# Determine correct Frida server version
FRIDA_VERSION="16.1.8"

# MuMu usually reports arm64 but may need special handling
if [[ "$ARCH" == *"arm64"* ]]; then
    FRIDA_ARCH="arm64"
    echo -e "${GREEN}   ✅ ARM64 architecture detected${NC}"
elif [[ "$ARCH" == *"x86_64"* ]]; then
    FRIDA_ARCH="x86_64"
    echo -e "${YELLOW}   ⚠️ x86_64 architecture detected (unusual for MuMu)${NC}"
else
    FRIDA_ARCH="arm"
    echo -e "${YELLOW}   ⚠️ 32-bit ARM architecture detected${NC}"
fi

# Download Frida server
FRIDA_SERVER="frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}"
FRIDA_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_SERVER}.xz"

echo ""
echo "📥 Preparing Frida server..."

if [ ! -f "${FRIDA_SERVER}" ]; then
    echo "   Downloading Frida server ${FRIDA_VERSION} for ${FRIDA_ARCH}..."
    curl -L -o "${FRIDA_SERVER}.xz" "$FRIDA_URL"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Failed to download Frida server${NC}"
        echo "   URL: $FRIDA_URL"
        exit 1
    fi
    
    echo "   Extracting..."
    unxz "${FRIDA_SERVER}.xz"
    chmod +x "${FRIDA_SERVER}"
    echo -e "${GREEN}   ✅ Frida server prepared${NC}"
else
    echo -e "${GREEN}   ✅ Using existing Frida server${NC}"
fi

# Push Frida server to device
echo ""
echo "📤 Installing Frida server to MuMu..."

# Kill existing Frida servers
echo "   Cleaning up old processes..."
adb shell "killall frida-server 2>/dev/null"
adb shell "killall frida-server-arm64 2>/dev/null"

# Push to multiple locations for compatibility
echo "   Pushing to device..."
adb push "${FRIDA_SERVER}" /data/local/tmp/frida-server
adb push "${FRIDA_SERVER}" /data/local/tmp/frida-server-${FRIDA_ARCH}

# Set permissions
echo "   Setting permissions..."
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "chmod 755 /data/local/tmp/frida-server-${FRIDA_ARCH}"

# Check root access and start server
echo ""
echo "🔐 Checking root access..."

ROOT_TEST=$(adb shell "su -c 'id'" 2>&1)
if echo "$ROOT_TEST" | grep -q "uid=0"; then
    echo -e "${GREEN}✅ Root access confirmed${NC}"
    
    # Start Frida server with proper parameters for MuMu
    echo ""
    echo "🚀 Starting Frida server..."
    
    # Use specific binding for MuMu compatibility
    adb shell "su -c 'nohup /data/local/tmp/frida-server -l 0.0.0.0:27042 > /dev/null 2>&1 &'"
    
    sleep 3
    
    # Verify Frida server is running
    FRIDA_PS=$(adb shell "ps | grep frida-server")
    if [ -n "$FRIDA_PS" ]; then
        echo -e "${GREEN}✅ Frida server is running${NC}"
        echo "   Process: $FRIDA_PS"
    else
        # Try alternative start method
        echo -e "${YELLOW}   Trying alternative start method...${NC}"
        adb shell "su -c '/data/local/tmp/frida-server -D &'"
        sleep 2
        
        FRIDA_PS=$(adb shell "ps | grep frida-server")
        if [ -n "$FRIDA_PS" ]; then
            echo -e "${GREEN}✅ Frida server started with alternative method${NC}"
        else
            echo -e "${YELLOW}⚠️ Frida server may not be running properly${NC}"
            echo "   The app will attempt to start it automatically"
        fi
    fi
else
    echo -e "${YELLOW}⚠️ Root access not available${NC}"
    echo "   Attempting to enable root in MuMu settings..."
    echo ""
    echo "   Please manually enable root in MuMu:"
    echo "   1. Open MuMu settings"
    echo "   2. Go to 'Other Settings'"
    echo "   3. Enable 'Root Permission'"
    echo "   4. Restart MuMu and run this script again"
fi

# Test Frida connectivity
echo ""
echo "🧪 Testing Frida connectivity..."

# Create a simple test script
cat > test_frida.py << 'EOF'
#!/usr/bin/env python3
import sys
try:
    import frida
    device = frida.get_usb_device(timeout=5)
    print(f"✅ Frida connection successful: {device}")
    processes = device.enumerate_processes()
    print(f"   Found {len(processes)} processes")
    sys.exit(0)
except Exception as e:
    print(f"❌ Frida connection failed: {e}")
    sys.exit(1)
EOF

if command -v python3 &> /dev/null; then
    python3 test_frida.py
    rm test_frida.py
else
    echo "   Python3 not found, skipping connectivity test"
fi

# Create helper files
echo ""
echo "📝 Creating helper files..."

# Create token file
adb shell "touch /sdcard/grab_order_token.json"
adb shell "chmod 666 /sdcard/grab_order_token.json"

# Create startup script for MuMu
adb shell "echo '#!/system/bin/sh' > /data/local/tmp/start_frida.sh"
adb shell "echo '/data/local/tmp/frida-server -l 0.0.0.0:27042 &' >> /data/local/tmp/start_frida.sh"
adb shell "chmod 755 /data/local/tmp/start_frida.sh"

echo -e "${GREEN}✅ Helper files created${NC}"

# Summary
echo ""
echo "========================================"
echo -e "${GREEN}✅ MuMu Frida Setup Complete!${NC}"
echo "========================================"
echo ""
echo "📋 Status Summary:"
echo "   • Architecture: ${FRIDA_ARCH}"
echo "   • Frida Version: ${FRIDA_VERSION}"
echo "   • Server Location: /data/local/tmp/frida-server"
if [ -n "$FRIDA_PS" ]; then
    echo -e "   • Server Status: ${GREEN}Running${NC}"
else
    echo -e "   • Server Status: ${YELLOW}Manual start required${NC}"
fi
echo ""
echo "📱 Next Steps:"
echo ""
echo "1. Install the app:"
echo "   adb install GrabOrderApp/bin/*.apk"
echo ""
echo "2. If Frida server is not running, start manually:"
echo "   adb shell 'su -c \"/data/local/tmp/frida-server -D &\"'"
echo ""
echo "3. Start the app and click 'Start'"
echo ""
echo "4. The app will automatically detect and use Frida"
echo ""
echo "💡 Troubleshooting:"
echo "   • If Frida fails, check: adb logcat | grep -i frida"
echo "   • Ensure target app is running before clicking Start"
echo "   • Try restarting MuMu if issues persist"
echo ""
