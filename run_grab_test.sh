#!/bin/bash
# Order Grab Test Launcher

echo "========================================"
echo "Order Grab Test with Geetest"
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

# Check for token
echo "Checking for login token..."
TOKEN_FILE=$(ls -t login_token_*.txt 2>/dev/null | head -1)

if [ -n "$TOKEN_FILE" ]; then
    echo "✅ Found token: $TOKEN_FILE"
    echo ""
else
    echo "❌ No token file found"
    echo ""
    echo "Please login first:"
    echo "  ./run_login_test.sh"
    echo ""
    echo "Or you can enter token manually when prompted"
    echo ""
fi

# Run test
echo "Starting order grab test..."
echo ""

python3 test_grab_order.py
