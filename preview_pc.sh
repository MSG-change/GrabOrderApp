#!/bin/bash
# PC预览脚本

echo "🚀 开始PC预览..."
echo ""

# 检查Python
if ! command -v python3 &> /dev/null; then
    echo "❌ 未找到Python3，请先安装Python3"
    exit 1
fi

echo "✅ Python版本: $(python3 --version)"

# 检查并安装依赖
echo ""
echo "📦 检查依赖..."

# 检查kivy
if ! python3 -c "import kivy" 2>/dev/null; then
    echo "⚠️ Kivy未安装，正在安装..."
    pip3 install kivy pillow
else
    echo "✅ Kivy已安装"
fi

# 检查其他依赖
python3 -c "import requests" 2>/dev/null || pip3 install requests

echo ""
echo "🎨 启动预览..."
echo "提示：按Ctrl+C退出"
echo ""

# 运行应用
python3 main.py

