#!/bin/bash
# Login Test Launcher

echo "========================================"
echo "Login Test with Geetest"
echo "========================================"
echo ""

# Set AI server URL
export AI_SERVER_URL=http://127.0.0.1:8889

# Check AI server
echo "Checking AI server..."
if curl -s http://127.0.0.1:8889/health > /dev/null 2>&1; then
    echo "✅ AI server is running"
else
    echo "❌ AI server not running"
    echo ""
    echo "Please start AI server first:"
    echo "  cd ../geetest_ai"
    echo "  python3 api_server.py"
    echo ""
    exit 1
fi

echo ""

# Check if Kivy is installed
if python3 -c "import kivy" 2>/dev/null; then
    echo "Starting login test app (UI version)..."
    echo ""
    python3 test_login_ui.py
else
    echo "Kivy not installed, using CLI version..."
    echo ""
    python3 test_login_cli.py
fi
