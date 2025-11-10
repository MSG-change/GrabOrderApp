#!/usr/bin/env python3
"""
测试手机号登录 + 远程AI识别九宫格验证码
完整流程测试
"""
import os
import sys
import requests
import time
import json

# 设置远程 AI 服务器
os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'

from libs.geetest_helper_local import GeetestHelper

# 配置
BASE_URL = "https://app.shunshunxiaozhan.com"
CAPTCHA_ID = "045e2c229998a88721e32a763bc0f7b8"

# 请求头
HEADERS = {
    'Host': 'app.shunshunxiaozhan.com',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 12; 23127PN0CC Build/W528JS; wv) AppleWebKit/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json;charset=UTF-8',
    'Origin': 'https://app.shunshunxiaozhan.com',
    'X-Requested-With': 'com.dys.shzs',
    'Referer': 'https://app.shunshunxiaozhan.com/',
}


def print_step(step, message):
    """打印步骤"""
    print(f"\n{'='*70}")
    print(f"{step} {message}")
    print('='*70)


def send_sms(phone):
    """发送短信验证码"""
    print_step("📱", "发送短信验证码")
    
    url = f"{BASE_URL}/driver/user/sendSms"
    data = {
        "phone": phone,
        "type": 1
    }
    
    print(f"手机号: {phone}")
    
    try:
        response = requests.post(url, json=data, headers=HEADERS, timeout=10)
        result = response.json()
        
        print(f"响应: {json.dumps(result, ensure_ascii=False, indent=2)}")
        
        if result.get('code') == 0:
            print("✅ 短信发送成功")
            return True
        else:
            print(f"❌ 短信发送失败: {result.get('msg')}")
            return False
            
    except Exception as e:
        print(f"❌ 发送短信异常: {e}")
        return False


def get_geetest_challenge(phone):
    """获取极验验证码 challenge"""
    print_step("🔐", "获取极验验证码 Challenge")
    
    url = f"{BASE_URL}/driver/user/getGeetestChallenge"
    data = {
        "phone": phone,
        "captchaId": CAPTCHA_ID
    }
    
    try:
        response = requests.post(url, json=data, headers=HEADERS, timeout=10)
        result = response.json()
        
        print(f"响应: {json.dumps(result, ensure_ascii=False, indent=2)}")
        
        if result.get('code') == 0:
            challenge_data = result.get('data', {})
            challenge = challenge_data.get('challenge')
            lot_number = challenge_data.get('lot_number')
            
            print(f"✅ Challenge 获取成功")
            print(f"   Challenge: {challenge}")
            print(f"   Lot Number: {lot_number}")
            
            return challenge, lot_number
        else:
            print(f"❌ Challenge 获取失败: {result.get('msg')}")
            return None, None
            
    except Exception as e:
        print(f"❌ 获取 Challenge 异常: {e}")
        return None, None


def solve_geetest_with_remote_ai(challenge, lot_number):
    """使用远程AI解决极验验证码"""
    print_step("🤖", "使用远程AI识别九宫格验证码")
    
    print(f"🌐 AI服务器: {os.environ['AI_SERVER_URL']}")
    print(f"Challenge: {challenge}")
    print(f"Lot Number: {lot_number}")
    
    try:
        # 初始化 GeetestHelper
        print("\n初始化 GeetestHelper...")
        helper = GeetestHelper()
        
        # 获取验证码图片
        print("\n获取验证码图片...")
        
        # 构造图片URL
        question_url = f"https://gcaptcha4.geetest.com/load?captcha_id={CAPTCHA_ID}&challenge={challenge}&client_type=web&lang=zh"
        
        # 调用 verify 方法（会自动处理整个流程）
        print("\n开始识别验证码...")
        result = helper.verify(challenge)
        
        if result and result.get('success'):
            print("\n✅ 验证码识别成功！")
            print(f"   Lot Number: {result.get('lot_number')}")
            print(f"   Captcha Output (W参数): {result.get('captcha_output')[:50]}...")
            print(f"   Pass Token: {result.get('pass_token')[:50]}...")
            print(f"   Gen Time: {result.get('gen_time')}")
            
            return result
        else:
            error = result.get('error') if result else '未知错误'
            print(f"\n❌ 验证码识别失败: {error}")
            return None
            
    except Exception as e:
        print(f"\n❌ 识别过程异常: {e}")
        import traceback
        traceback.print_exc()
        return None


def login_with_sms(phone, sms_code, geetest_result):
    """使用短信验证码和极验结果登录"""
    print_step("🔑", "登录")
    
    url = f"{BASE_URL}/driver/user/loginBySms"
    
    # 构造 geeDto
    gee_dto = {
        'lotNumber': geetest_result.get('lot_number'),
        'captchaOutput': geetest_result.get('captcha_output'),
        'passToken': geetest_result.get('pass_token'),
        'genTime': geetest_result.get('gen_time'),
        'captchaId': CAPTCHA_ID,
        'captchaKeyType': 'dlVerify'
    }
    
    data = {
        "phone": phone,
        "code": sms_code,
        "geeDto": gee_dto
    }
    
    print(f"手机号: {phone}")
    print(f"验证码: {sms_code}")
    print(f"GeeDto: {json.dumps(gee_dto, ensure_ascii=False, indent=2)}")
    
    try:
        response = requests.post(url, json=data, headers=HEADERS, timeout=10)
        result = response.json()
        
        print(f"\n响应: {json.dumps(result, ensure_ascii=False, indent=2)}")
        
        if result.get('code') == 0:
            print("\n✅ 登录成功！")
            token = result.get('data', {}).get('token')
            print(f"Token: {token[:50]}..." if token else "Token: None")
            return True, token
        else:
            print(f"\n❌ 登录失败: {result.get('msg')}")
            return False, None
            
    except Exception as e:
        print(f"\n❌ 登录异常: {e}")
        return False, None


def main():
    """主测试流程"""
    print("\n" + "🚀 " * 30)
    print("手机号登录 + 远程AI识别九宫格验证码 - 完整测试")
    print("🚀 " * 30)
    
    # 输入手机号
    phone = input("\n请输入手机号: ").strip()
    if not phone:
        print("❌ 手机号不能为空")
        return
    
    # 步骤1: 发送短信
    if not send_sms(phone):
        print("\n❌ 测试终止：短信发送失败")
        return
    
    # 步骤2: 获取 Challenge
    challenge, lot_number = get_geetest_challenge(phone)
    if not challenge:
        print("\n❌ 测试终止：Challenge 获取失败")
        return
    
    # 步骤3: 使用远程AI识别验证码
    geetest_result = solve_geetest_with_remote_ai(challenge, lot_number)
    if not geetest_result:
        print("\n❌ 测试终止：验证码识别失败")
        return
    
    # 步骤4: 输入短信验证码
    sms_code = input("\n请输入收到的短信验证码: ").strip()
    if not sms_code:
        print("❌ 验证码不能为空")
        return
    
    # 步骤5: 登录
    success, token = login_with_sms(phone, sms_code, geetest_result)
    
    # 总结
    print("\n" + "=" * 70)
    print("📊 测试总结")
    print("=" * 70)
    print(f"✅ 短信发送: 成功")
    print(f"✅ Challenge获取: 成功")
    print(f"✅ 远程AI识别: {'成功' if geetest_result else '失败'}")
    print(f"{'✅' if success else '❌'} 登录: {'成功' if success else '失败'}")
    
    if success:
        print("\n🎉 完整流程测试通过！")
        print(f"🌐 远程AI服务器工作正常: {os.environ['AI_SERVER_URL']}")
    else:
        print("\n⚠️  登录失败，但远程AI识别功能已验证")
    
    print("=" * 70 + "\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  测试被用户中断")
    except Exception as e:
        print(f"\n\n❌ 测试异常: {e}")
        import traceback
        traceback.print_exc()
