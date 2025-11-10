#!/bin/bash
# 启动AI服务器（在Mac上运行）

echo "🚀 启动远程AI服务器"
echo "=================================="

# 检查依赖
echo "📦 检查依赖..."
python3 -c "import flask" 2>/dev/null || {
    echo "安装Flask..."
    pip3 install flask
}

python3 -c "import PIL" 2>/dev/null || {
    echo "安装Pillow..."
    pip3 install pillow
}

# 获取本机IP
echo ""
echo "📡 本机IP地址："
ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print "   " $2}'

echo ""
echo "🔧 配置说明："
echo "   1. 记下上面的IP地址（比如 192.168.1.100）"
echo "   2. 在手机Termux中设置环境变量："
echo "      export AI_SERVER_URL=http://你的IP:8888"
echo "   3. 或者修改 remote_ai_helper.py 中的默认地址"
echo ""

# 启动服务
echo "🚀 启动AI服务（端口8888）..."
echo "   按 Ctrl+C 停止服务"
echo ""

cd "$(dirname "$0")"
python3 hybrid_solution.py
