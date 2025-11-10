#!/usr/bin/env python3
"""
完整流程测试 - 自动获取 challenge 并测试远程 AI
"""
import os
import sys
import requests
import json

# 设置远程 AI
os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'

# 配置
PHONE = "18113011654"
CAPTCHA_ID = "045e2c229998a88721e32a763bc0f7b8"
BASE_URL = "https://app.shunshunxiaozhan.com"

print("\n" + "🚀 " * 30)
print("完整流程测试 - 自动获取 challenge 并识别")
print("🚀 " * 30 + "\n")

# ============================================================================
# 步骤1: 测试 AI 服务器
# ============================================================================
print("=" * 70)
print("步骤1: 测试 AI 服务器连接")
print("=" * 70)

try:
    response = requests.get('http://154.219.127.13:8889/health', timeout=5)
    if response.status_code == 200:
        data = response.json()
        print(f"✅ AI 服务器在线")
        print(f"   状态: {data.get('status')}")
        print(f"   模型已加载: {data.get('model_loaded')}")
    else:
        print(f"❌ AI 服务器响应异常: {response.status_code}")
        sys.exit(1)
except Exception as e:
    print(f"❌ AI 服务器连接失败: {e}")
    sys.exit(1)

# ============================================================================
# 步骤2: 获取 Challenge
# ============================================================================
print("\n" + "=" * 70)
print("步骤2: 获取 Geetest Challenge")
print("=" * 70)
print(f"手机号: {PHONE}")
print(f"Captcha ID: {CAPTCHA_ID}")

challenge_url = f"{BASE_URL}/driver/user/getGeetestChallenge"
challenge_data = {
    "phone": PHONE,
    "captchaId": CAPTCHA_ID
}

headers = {
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36'
}

try:
    print(f"\n正在请求: {challenge_url}")
    response = requests.post(
        challenge_url, 
        json=challenge_data, 
        headers=headers,
        timeout=10
    )
    
    print(f"响应状态码: {response.status_code}")
    
    if response.status_code != 200:
        print(f"❌ 请求失败")
        print(f"响应内容: {response.text}")
        sys.exit(1)
    
    result = response.json()
    print(f"\n响应内容:")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    
    if result.get('code') != 0:
        print(f"\n❌ 获取 Challenge 失败: {result.get('msg')}")
        sys.exit(1)
    
    challenge_info = result.get('data', {})
    challenge = challenge_info.get('challenge')
    lot_number = challenge_info.get('lot_number')
    
    if not challenge:
        print(f"❌ 响应中没有 challenge")
        sys.exit(1)
    
    print(f"\n✅ Challenge 获取成功")
    print(f"   Challenge: {challenge}")
    print(f"   Lot Number: {lot_number}")
    
except requests.exceptions.SSLError as e:
    print(f"\n❌ SSL 连接错误: {e}")
    print("\n💡 解决方法:")
    print("   1. 检查网络连接")
    print("   2. 尝试使用 VPN")
    print("   3. 或在服务器上运行此脚本")
    sys.exit(1)
except requests.exceptions.ConnectionError as e:
    print(f"\n❌ 网络连接错误: {e}")
    print("\n💡 解决方法:")
    print("   1. 检查网络连接")
    print("   2. 确认 API 地址正确")
    sys.exit(1)
except Exception as e:
    print(f"\n❌ 请求异常: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# ============================================================================
# 步骤3: 使用远程 AI 识别验证码
# ============================================================================
print("\n" + "=" * 70)
print("步骤3: 使用远程 AI 识别验证码")
print("=" * 70)

try:
    from libs.geetest_helper_local import GeetestHelper
    
    print("初始化 GeetestHelper...")
    helper = GeetestHelper(captcha_id=CAPTCHA_ID)
    print(f"✅ 初始化成功")
    print(f"   使用远程AI: {helper.model is None}")
    
    print(f"\n开始识别验证码...")
    print(f"   Challenge: {challenge[:50]}...")
    print(f"   正在获取验证码图片...")
    print(f"   正在调用远程 AI 识别...")
    print(f"   (这可能需要几秒钟...)")
    
    geetest_result = helper.verify(challenge)
    
    if geetest_result and geetest_result.get('success'):
        print("\n" + "=" * 70)
        print("✅ 验证码识别成功！")
        print("=" * 70)
        
        print("\n完整结果:")
        print(json.dumps(geetest_result, ensure_ascii=False, indent=2))
        
        print("\n" + "=" * 70)
        print("🎯 关键信息（用于登录/抢单）:")
        print("=" * 70)
        print(f"Lot Number:      {geetest_result.get('lot_number')}")
        print(f"Pass Token:      {geetest_result.get('pass_token')[:50]}..." if geetest_result.get('pass_token') else "Pass Token:      None")
        print(f"Captcha Output:  {geetest_result.get('captcha_output')[:50]}..." if geetest_result.get('captcha_output') else "Captcha Output:  None")
        print(f"Gen Time:        {geetest_result.get('gen_time')}")
        
        if geetest_result.get('answers'):
            print(f"\n识别答案: {geetest_result.get('answers')}")
        
        # 生成 geeDto
        print("\n" + "=" * 70)
        print("📋 生成的 geeDto（可直接用于登录/抢单）:")
        print("=" * 70)
        
        gee_dto = {
            'lotNumber': geetest_result.get('lot_number'),
            'captchaOutput': geetest_result.get('captcha_output'),
            'passToken': geetest_result.get('pass_token'),
            'genTime': geetest_result.get('gen_time'),
            'captchaId': CAPTCHA_ID,
            'captchaKeyType': 'dlVerify'
        }
        
        print(json.dumps(gee_dto, ensure_ascii=False, indent=2))
        
        print("\n" + "=" * 70)
        print("🎉 完整流程测试成功！")
        print("=" * 70)
        print("\n✅ 所有步骤:")
        print("   1. AI 服务器连接 - 成功")
        print("   2. 获取 Challenge - 成功")
        print("   3. 远程 AI 识别 - 成功")
        print("\n🌐 远程 AI 服务器工作正常: http://154.219.127.13:8889")
        print("=" * 70)
        
    else:
        error = geetest_result.get('error') if geetest_result else '未知错误'
        print(f"\n❌ 验证码识别失败: {error}")
        if geetest_result:
            print("\n详细信息:")
            print(json.dumps(geetest_result, ensure_ascii=False, indent=2))
        sys.exit(1)
        
except ImportError as e:
    print(f"\n❌ 模块导入失败: {e}")
    print("\n💡 解决方法:")
    print("   cd /Users/duanzubin/develop/script/siam-autolabel/GrabOrderApp")
    print("   pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"\n❌ 识别过程异常: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n")
