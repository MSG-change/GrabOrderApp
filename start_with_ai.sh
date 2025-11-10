#!/bin/bash
# 加载环境变量
if [ -f .env ]; then
    export $(cat .env | xargs)
fi

echo "🚀 启动抢单APP"
echo "🌐 AI服务器: $AI_SERVER_URL"
python main.py
