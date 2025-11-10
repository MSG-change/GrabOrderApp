#!/usr/bin/env python3
"""
快速获取 Geetest Challenge
"""
import requests
import json
import sys

BASE_URL = "https://app.shunshunxiaozhan.com"
CAPTCHA_ID = "045e2c229998a88721e32a763bc0f7b8"

HEADERS = {
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36',
}


def get_challenge(phone):
    """获取 challenge"""
    print("=" * 70)
    print("📱 获取 Geetest Challenge")
    print("=" * 70)
    print(f"手机号: {phone}")
    print(f"Captcha ID: {CAPTCHA_ID}")
    print()
    
    url = f"{BASE_URL}/driver/user/getGeetestChallenge"
    data = {
        "phone": phone,
        "captchaId": CAPTCHA_ID
    }
    
    try:
        response = requests.post(url, json=data, headers=HEADERS, timeout=10)
        result = response.json()
        
        print("响应:")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        print()
        
        if result.get('code') == 0:
            challenge_data = result.get('data', {})
            challenge = challenge_data.get('challenge')
            lot_number = challenge_data.get('lot_number')
            
            print("=" * 70)
            print("✅ Challenge 获取成功")
            print("=" * 70)
            print(f"Challenge: {challenge}")
            print(f"Lot Number: {lot_number}")
            print()
            print("=" * 70)
            print("🚀 下一步：测试远程 AI 识别")
            print("=" * 70)
            print("运行以下命令:")
            print(f"  python test_ai_with_challenge.py '{challenge}'")
            print()
            print("或者运行完整测试:")
            print(f"  python test_ai_with_challenge.py '{challenge}' '{CAPTCHA_ID}'")
            print("=" * 70)
            
            return challenge, lot_number
        else:
            print(f"❌ 获取失败: {result.get('msg')}")
            return None, None
            
    except Exception as e:
        print(f"❌ 请求异常: {e}")
        return None, None


def main():
    """主函数"""
    print("\n" + "🔐 " * 30)
    print("快速获取 Geetest Challenge")
    print("🔐 " * 30 + "\n")
    
    if len(sys.argv) >= 2:
        phone = sys.argv[1]
        get_challenge(phone)
    else:
        print("使用方法:")
        print(f"  python {sys.argv[0]} <手机号>")
        print()
        print("示例:")
        print(f"  python {sys.argv[0]} 13800138000")
        print()


if __name__ == '__main__':
    main()
