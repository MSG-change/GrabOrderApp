#!/bin/bash
# 一键测试远程 AI（使用 challenge）

echo "================================"
echo "🚀 一键测试远程 AI"
echo "================================"
echo ""

if [ -z "$1" ]; then
    echo "使用方法:"
    echo "  ./quick_test_ai.sh <手机号>"
    echo ""
    echo "示例:"
    echo "  ./quick_test_ai.sh 13800138000"
    echo ""
    echo "流程:"
    echo "  1. 获取 Geetest Challenge"
    echo "  2. 使用远程 AI 识别验证码"
    echo "  3. 显示识别结果"
    echo ""
    exit 1
fi

PHONE=$1

echo "手机号: $PHONE"
echo "AI服务器: http://154.219.127.13:8889"
echo ""

# 步骤1: 获取 Challenge
echo "================================"
echo "步骤1: 获取 Challenge"
echo "================================"

RESULT=$(python3 -c "
import requests
import json

url = 'https://app.shunshunxiaozhan.com/driver/user/getGeetestChallenge'
data = {'phone': '$PHONE', 'captchaId': '045e2c229998a88721e32a763bc0f7b8'}
headers = {'Content-Type': 'application/json'}

try:
    response = requests.post(url, json=data, headers=headers, timeout=10)
    result = response.json()
    if result.get('code') == 0:
        challenge = result['data']['challenge']
        print(challenge)
    else:
        print('ERROR:' + result.get('msg', '未知错误'))
except Exception as e:
    print('ERROR:' + str(e))
")

if [[ $RESULT == ERROR:* ]]; then
    echo "❌ 获取 Challenge 失败: ${RESULT#ERROR:}"
    exit 1
fi

CHALLENGE=$RESULT
echo "✅ Challenge: $CHALLENGE"
echo ""

# 步骤2: 测试远程 AI 识别
echo "================================"
echo "步骤2: 使用远程 AI 识别"
echo "================================"
echo ""

python test_ai_with_challenge.py "$CHALLENGE"

echo ""
echo "================================"
echo "✅ 测试完成"
echo "================================"
