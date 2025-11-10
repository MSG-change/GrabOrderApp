#!/usr/bin/env python3
"""
手动输入 challenge 测试远程 AI
适用于网络问题或需要手动获取 challenge 的情况
"""
import os
import sys

os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'

from libs.geetest_helper_local import GeetestHelper


def main():
    print("\n" + "🤖 " * 30)
    print("远程 AI 验证码识别测试（手动输入）")
    print("🤖 " * 30 + "\n")
    
    print("=" * 70)
    print("📝 使用说明")
    print("=" * 70)
    print("1. 通过任何方式获取 Geetest Challenge")
    print("2. 将 Challenge 粘贴到下面")
    print("3. 远程 AI 将自动识别验证码")
    print()
    print("获取 Challenge 的方法:")
    print("  - 使用 Postman/curl 调用 getGeetestChallenge 接口")
    print("  - 从浏览器开发者工具的 Network 标签中复制")
    print("  - 从 APP 日志中获取")
    print("=" * 70)
    print()
    
    # 输入 challenge
    challenge = input("请输入 Challenge: ").strip()
    
    if not challenge:
        print("❌ Challenge 不能为空")
        return
    
    # 可选：输入 captcha_id
    captcha_id = input("请输入 Captcha ID (直接回车使用默认值): ").strip()
    if not captcha_id:
        captcha_id = "045e2c229998a88721e32a763bc0f7b8"
    
    print()
    print("=" * 70)
    print("🚀 开始测试")
    print("=" * 70)
    print(f"🌐 AI服务器: {os.environ['AI_SERVER_URL']}")
    print(f"📝 Captcha ID: {captcha_id}")
    print(f"📝 Challenge: {challenge[:50]}...")
    print("=" * 70)
    print()
    
    try:
        # 初始化
        print("1️⃣  初始化 GeetestHelper...")
        helper = GeetestHelper(captcha_id=captcha_id)
        print("   ✅ 初始化成功")
        print(f"   使用远程AI: {helper.model is None}")
        
        # 识别
        print("\n2️⃣  开始识别验证码...")
        print("   正在获取验证码图片...")
        print("   正在调用远程AI识别...")
        print("   (这可能需要几秒钟...)")
        
        result = helper.verify(challenge)
        
        if result and result.get('success'):
            print("\n" + "=" * 70)
            print("✅ 验证码识别成功！")
            print("=" * 70)
            
            import json
            print("\n完整结果:")
            print(json.dumps(result, ensure_ascii=False, indent=2))
            
            print("\n" + "=" * 70)
            print("🎯 关键信息（用于登录）:")
            print("=" * 70)
            print(f"Lot Number:      {result.get('lot_number')}")
            print(f"Pass Token:      {result.get('pass_token')[:50]}..." if result.get('pass_token') else "Pass Token:      None")
            print(f"Captcha Output:  {result.get('captcha_output')[:50]}..." if result.get('captcha_output') else "Captcha Output:  None")
            print(f"Gen Time:        {result.get('gen_time')}")
            
            if result.get('answers'):
                print(f"\n识别答案: {result.get('answers')}")
            
            print("\n" + "=" * 70)
            print("🎉 测试成功！远程 AI 工作正常")
            print("=" * 70)
            
            # 生成登录用的 geeDto
            print("\n" + "=" * 70)
            print("📋 登录用的 geeDto:")
            print("=" * 70)
            gee_dto = {
                'lotNumber': result.get('lot_number'),
                'captchaOutput': result.get('captcha_output'),
                'passToken': result.get('pass_token'),
                'genTime': result.get('gen_time'),
                'captchaId': captcha_id,
                'captchaKeyType': 'dlVerify'
            }
            print(json.dumps(gee_dto, ensure_ascii=False, indent=2))
            print("=" * 70)
            
        else:
            error = result.get('error') if result else '未知错误'
            print(f"\n❌ 验证码识别失败: {error}")
            if result:
                import json
                print("\n详细信息:")
                print(json.dumps(result, ensure_ascii=False, indent=2))
        
    except Exception as e:
        print(f"\n❌ 测试异常: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  测试被用户中断")
    except Exception as e:
        print(f"\n❌ 程序异常: {e}")
        import traceback
        traceback.print_exc()
