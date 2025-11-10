#!/usr/bin/env python3
"""
使用 captcha_id 和 challenge 直接测试远程 AI
最简单的测试方式
"""
import os
import sys
import json

# 设置远程 AI
os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'

from libs.geetest_helper_local import GeetestHelper


def test_with_challenge(captcha_id, challenge):
    """使用 challenge 测试验证码识别"""
    print("=" * 70)
    print("🤖 使用远程 AI 识别九宫格验证码")
    print("=" * 70)
    print(f"🌐 AI服务器: {os.environ['AI_SERVER_URL']}")
    print(f"📝 Captcha ID: {captcha_id}")
    print(f"📝 Challenge: {challenge}")
    print("=" * 70)
    
    try:
        # 初始化 GeetestHelper
        print("\n1️⃣  初始化 GeetestHelper...")
        helper = GeetestHelper(captcha_id=captcha_id)
        print("   ✅ 初始化成功")
        print(f"   使用远程AI: {helper.model is None}")
        
        # 调用 verify 方法
        print("\n2️⃣  开始识别验证码...")
        print("   正在获取验证码图片...")
        print("   正在调用远程AI识别...")
        
        result = helper.verify(challenge)
        
        if result and result.get('success'):
            print("\n✅ 验证码识别成功！")
            print("=" * 70)
            print("📊 识别结果:")
            print("=" * 70)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            
            print("\n🎯 关键信息:")
            print(f"   Lot Number: {result.get('lot_number')}")
            print(f"   Pass Token: {result.get('pass_token')[:50]}..." if result.get('pass_token') else "   Pass Token: None")
            print(f"   Captcha Output (W参数): {result.get('captcha_output')[:50]}..." if result.get('captcha_output') else "   Captcha Output: None")
            print(f"   Gen Time: {result.get('gen_time')}")
            
            if result.get('answers'):
                print(f"\n   识别答案: {result.get('answers')}")
            
            print("\n" + "=" * 70)
            print("🎉 测试成功！远程 AI 工作正常")
            print("=" * 70)
            
            return True
        else:
            error = result.get('error') if result else '未知错误'
            print(f"\n❌ 验证码识别失败: {error}")
            if result:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            return False
            
    except Exception as e:
        print(f"\n❌ 测试异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """主函数"""
    print("\n" + "🚀 " * 30)
    print("远程 AI 验证码识别测试")
    print("🚀 " * 30 + "\n")
    
    # 默认值
    default_captcha_id = "045e2c229998a88721e32a763bc0f7b8"
    
    # 从命令行参数获取
    if len(sys.argv) >= 2:
        challenge = sys.argv[1]
        captcha_id = sys.argv[2] if len(sys.argv) >= 3 else default_captcha_id
        
        print(f"使用参数:")
        print(f"  Challenge: {challenge}")
        print(f"  Captcha ID: {captcha_id}")
        print()
        
        success = test_with_challenge(captcha_id, challenge)
        
        if success:
            print("\n✅ 所有测试通过")
            sys.exit(0)
        else:
            print("\n❌ 测试失败")
            sys.exit(1)
    else:
        print("使用方法:")
        print(f"  python {sys.argv[0]} <challenge> [captcha_id]")
        print()
        print("参数说明:")
        print("  challenge   - 必需，从 getGeetestChallenge 接口获取")
        print("  captcha_id  - 可选，默认为 045e2c229998a88721e32a763bc0f7b8")
        print()
        print("示例:")
        print(f"  python {sys.argv[0]} 'abc123def456...'")
        print(f"  python {sys.argv[0]} 'abc123def456...' '045e2c229998a88721e32a763bc0f7b8'")
        print()
        print("获取 challenge 的方法:")
        print("  1. 运行登录流程:")
        print("     python test_login_with_remote_ai.py")
        print()
        print("  2. 或直接调用 API:")
        print("     curl -X POST https://app.shunshunxiaozhan.com/driver/user/getGeetestChallenge \\")
        print("       -H 'Content-Type: application/json' \\")
        print("       -d '{\"phone\":\"13800138000\",\"captchaId\":\"045e2c229998a88721e32a763bc0f7b8\"}'")
        print()
        print("  3. 从返回的 JSON 中提取 challenge 字段")
        print()


if __name__ == '__main__':
    main()
