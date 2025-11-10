#!/bin/bash
# 使用云服务器AI启动APP

# 设置云服务器AI地址
export AI_SERVER_URL=http://154.219.127.13:8889

echo "========================================"
echo "快速抢单助手 - 云AI模式"
echo "========================================"
echo ""
echo "AI服务器: $AI_SERVER_URL"
echo ""

# 检查服务器状态
echo "检查AI服务器状态..."
if curl -s --connect-timeout 5 "$AI_SERVER_URL/health" > /dev/null 2>&1; then
    echo "✅ AI服务器在线"
else
    echo "❌ AI服务器离线或无法访问"
    echo "   请检查:"
    echo "   1. 服务器是否启动"
    echo "   2. 防火墙是否开放8889端口"
    echo "   3. 网络连接是否正常"
    echo ""
    read -p "是否继续启动? (y/n): " continue_start
    if [ "$continue_start" != "y" ]; then
        exit 1
    fi
fi

echo ""
echo "启动APP..."
echo ""

# 启动APP
python main.py
