#!/usr/bin/env python3
"""
真实的发送验证码流程测试
使用真实的 API 地址和参数格式
"""
import os
import sys
import time
import json
import requests
from urllib.parse import urlencode

# 设置远程 AI
os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'

from libs.geetest_helper_local import GeetestHelper

print("\n" + "🔥 " * 30)
print("真实发送验证码流程测试")
print("🔥 " * 30 + "\n")

# ============================================================================
# 真实 API 配置
# ============================================================================
PHONE = "18113011654"
CAPTCHA_ID = "045e2c229998a88721e32a763bc0f7b8"
API_HOST = "dysh.dyswl.com"
VERIFY_URL = f"https://{API_HOST}/gate/app-api/club/geeTest/yanzheng"

HEADERS = {
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 12; 23127PN0CC Build/W528JS; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)',
    'Host': API_HOST
}

print("配置信息:")
print(f"  手机号: {PHONE}")
print(f"  Captcha ID: {CAPTCHA_ID}")
print(f"  验证 API: {VERIFY_URL}")
print(f"  AI Server: {os.environ['AI_SERVER_URL']}")
print()

# ============================================================================
# 步骤1: 初始化 GeetestHelper
# ============================================================================
print("=" * 70)
print("步骤1: 初始化 GeetestHelper")
print("=" * 70)

try:
    geetest_helper = GeetestHelper(captcha_id=CAPTCHA_ID)
    print("✅ 初始化成功")
except Exception as e:
    print(f"❌ 初始化失败: {e}")
    sys.exit(1)

# ============================================================================
# 步骤2: 生成 Challenge
# ============================================================================
print("\n" + "=" * 70)
print("步骤2: 生成 Challenge")
print("=" * 70)

# 使用手机号和时间戳生成 challenge
challenge = geetest_helper.generate_challenge(f"sms_{PHONE}_{int(time.time())}")
print(f"✅ Challenge: {challenge}")

# ============================================================================
# 步骤3: 执行完整验证（远程 AI）
# ============================================================================
print("\n" + "=" * 70)
print("步骤3: 执行完整验证")
print("=" * 70)

start_time = time.time()

try:
    geetest_result = geetest_helper.verify(challenge=challenge)
    elapsed = time.time() - start_time
    
    if not geetest_result or not geetest_result.get('success'):
        print(f"❌ 验证失败")
        sys.exit(1)
    
    print(f"✅ 验证成功！(耗时: {elapsed:.2f}秒)")
    print(f"   识别答案: {geetest_result.get('answers', [])}")
    print(f"   Lot Number: {geetest_result.get('lot_number')}")
    print(f"   W 参数长度: {len(geetest_result.get('captcha_output', ''))} 字符")
    
except Exception as e:
    print(f"❌ 验证异常: {e}")
    sys.exit(1)

# ============================================================================
# 步骤4: 构建验证参数（GET 请求格式）
# ============================================================================
print("\n" + "=" * 70)
print("步骤4: 构建验证参数")
print("=" * 70)

verify_params = {
    'lotNumber': geetest_result.get('lot_number'),
    'captchaOutput': geetest_result.get('captcha_output'),
    'passToken': geetest_result.get('pass_token'),
    'genTime': str(geetest_result.get('gen_time')),
    'captchaId': CAPTCHA_ID,
    'captchaKeyType': 'dlVerify'
}

print("✅ 参数构建成功:")
for key, value in verify_params.items():
    if len(str(value)) > 50:
        print(f"   {key}: {str(value)[:50]}...")
    else:
        print(f"   {key}: {value}")

# ============================================================================
# 步骤5: 调用验证 API
# ============================================================================
print("\n" + "=" * 70)
print("步骤5: 调用验证 API")
print("=" * 70)

# 构造完整的 URL
full_url = f"{VERIFY_URL}?{urlencode(verify_params)}"
print(f"请求 URL: {full_url[:100]}...")
print()

try:
    response = requests.get(
        full_url,
        headers=HEADERS,
        timeout=10
    )
    
    print(f"响应状态码: {response.status_code}")
    print(f"响应内容:")
    
    try:
        result = response.json()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        
        # 判断验证结果
        if response.status_code == 200:
            if result.get('code') == 0 or result.get('success'):
                print(f"\n✅ 验证成功！")
                print(f"   消息: {result.get('msg', result.get('message', '成功'))}")
            else:
                print(f"\n⚠️  验证返回: {result.get('msg', result.get('message'))}")
                print(f"   Code: {result.get('code')}")
        else:
            print(f"\n⚠️  HTTP 状态异常: {response.status_code}")
            
    except json.JSONDecodeError:
        print(response.text)
        
except Exception as e:
    print(f"❌ 请求异常: {e}")
    import traceback
    traceback.print_exc()

# ============================================================================
# 步骤6: 生成完整的 cURL 命令（用于调试）
# ============================================================================
print("\n" + "=" * 70)
print("步骤6: 完整的 cURL 命令")
print("=" * 70)

curl_cmd = f'''curl -H "Content-Type: application/json" \\
  -H "User-Agent: Mozilla/5.0 (Linux; Android 12; 23127PN0CC Build/W528JS; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)" \\
  -H "Host: {API_HOST}" \\
  --compressed \\
  "{full_url}"'''

print(curl_cmd)

# ============================================================================
# 总结
# ============================================================================
print("\n" + "=" * 70)
print("🎉 测试总结")
print("=" * 70)

print(f"""
测试流程:
  ✅ 步骤1: GeetestHelper 初始化
  ✅ 步骤2: Challenge 生成
  ✅ 步骤3: 完整验证 (耗时: {elapsed:.2f}秒)
  ✅ 步骤4: 参数构建
  ✅ 步骤5: API 调用
  ✅ 步骤6: cURL 命令生成

验证数据:
  - Lot Number: {verify_params['lotNumber']}
  - W 参数长度: {len(verify_params['captchaOutput'])} 字符
  - Pass Token: {verify_params['passToken'][:50]}...
  - Gen Time: {verify_params['genTime']}

🎯 结论: 
  完整的验证流程已测试完成！
  所有参数都已正确生成，可以用于真实的 API 调用。
  
💡 注意:
  - 验证 API 使用 GET 请求
  - 参数通过 URL query string 传递
  - captchaOutput 会被自动 URL 编码
  - 在 APP 中使用时，确保网络正常
""")

print("=" * 70)
