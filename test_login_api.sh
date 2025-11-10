#!/bin/bash
# 手机号登录测试脚本（使用远程AI）

echo "================================"
echo "🚀 手机号登录 + 远程AI测试"
echo "================================"
echo ""
echo "使用方法:"
echo "  ./test_login_api.sh 手机号"
echo ""
echo "例如:"
echo "  ./test_login_api.sh 13800138000"
echo ""
echo "================================"
echo ""

if [ -z "$1" ]; then
    echo "请提供手机号作为参数"
    echo "例如: ./test_login_api.sh 13800138000"
    exit 1
fi

PHONE=$1

echo "手机号: $PHONE"
echo "AI服务器: http://154.219.127.13:8889"
echo ""
echo "开始测试..."
echo ""

# 运行Python脚本
python3 << EOF
import os
import sys
import requests
import json

os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'

phone = "$PHONE"
BASE_URL = "https://app.shunshunxiaozhan.com"
CAPTCHA_ID = "045e2c229998a88721e32a763bc0f7b8"

HEADERS = {
    'Host': 'app.shunshunxiaozhan.com',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 12; 23127PN0CC Build/W528JS; wv) AppleWebKit/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json;charset=UTF-8',
    'Origin': 'https://app.shunshunxiaozhan.com',
    'X-Requested-With': 'com.dys.shzs',
    'Referer': 'https://app.shunshunxiaozhan.com/',
}

print("=" * 70)
print("步骤1: 发送短信验证码")
print("=" * 70)

url = f"{BASE_URL}/driver/user/sendSms"
data = {"phone": phone, "type": 1}

try:
    response = requests.post(url, json=data, headers=HEADERS, timeout=10)
    result = response.json()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    
    if result.get('code') == 0:
        print("✅ 短信发送成功")
    else:
        print(f"❌ 短信发送失败: {result.get('msg')}")
        sys.exit(1)
except Exception as e:
    print(f"❌ 异常: {e}")
    sys.exit(1)

print("\n" + "=" * 70)
print("步骤2: 获取极验 Challenge")
print("=" * 70)

url = f"{BASE_URL}/driver/user/getGeetestChallenge"
data = {"phone": phone, "captchaId": CAPTCHA_ID}

try:
    response = requests.post(url, json=data, headers=HEADERS, timeout=10)
    result = response.json()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    
    if result.get('code') == 0:
        challenge_data = result.get('data', {})
        challenge = challenge_data.get('challenge')
        lot_number = challenge_data.get('lot_number')
        
        print(f"✅ Challenge 获取成功")
        print(f"   Challenge: {challenge}")
        print(f"   Lot Number: {lot_number}")
        
        # 保存到文件供后续使用
        with open('/tmp/geetest_challenge.json', 'w') as f:
            json.dump({'challenge': challenge, 'lot_number': lot_number, 'phone': phone}, f)
        
        print(f"\n📝 Challenge 已保存到 /tmp/geetest_challenge.json")
        print(f"\n下一步:")
        print(f"  1. 运行: python test_login_with_remote_ai.py")
        print(f"  2. 或手动调用远程AI API识别验证码")
        
    else:
        print(f"❌ Challenge 获取失败: {result.get('msg')}")
        sys.exit(1)
        
except Exception as e:
    print(f"❌ 异常: {e}")
    sys.exit(1)

print("\n" + "=" * 70)
print("步骤3: 测试远程AI连接")
print("=" * 70)

ai_url = os.environ['AI_SERVER_URL']
try:
    response = requests.get(f"{ai_url}/health", timeout=5)
    if response.status_code == 200:
        data = response.json()
        print(f"✅ AI服务器在线")
        print(f"   状态: {data.get('status')}")
        print(f"   模型已加载: {data.get('model_loaded')}")
    else:
        print(f"⚠️  AI服务器响应异常: {response.status_code}")
except Exception as e:
    print(f"❌ AI服务器连接失败: {e}")

print("\n" + "=" * 70)
print("✅ 前置步骤完成")
print("=" * 70)
print("\n现在需要:")
print("  1. 使用 GeetestHelper 识别验证码")
print("  2. 输入收到的短信验证码")
print("  3. 完成登录")
print("\n运行完整测试:")
print(f"  python test_login_with_remote_ai.py")
print("")

EOF
