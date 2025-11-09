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
echo "Starting login test app..."
echo ""

# Run test app
python3 test_login_ui.py
