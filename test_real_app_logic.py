#!/usr/bin/env python3
"""
使用 APP 真实逻辑测试 - 完全模拟 fast_grab_service.py 的流程
"""
import os
import sys
import time

# 设置远程 AI
os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'

from libs.geetest_helper_local import GeetestHelper

print("\n" + "🎯 " * 30)
print("使用 APP 真实逻辑测试")
print("🎯 " * 30 + "\n")

print("模拟场景: 抢单需要验证码")
print(f"AI 服务器: {os.environ['AI_SERVER_URL']}")
print()

# ============================================================================
# 完全按照 fast_grab_service.py 的逻辑
# ============================================================================

try:
    # 步骤1: 初始化 GeetestHelper（和 APP 一样）
    print("=" * 70)
    print("步骤1: 初始化 GeetestHelper")
    print("=" * 70)
    
    geetest_helper = GeetestHelper(captcha_id='045e2c229998a88721e32a763bc0f7b8')
    
    print(f"✅ 初始化成功")
    print(f"   使用远程AI: {geetest_helper.model is None}")
    print(f"   Captcha ID: {geetest_helper.captcha_id}")
    
    # 步骤2: 生成 challenge（和 APP 一样）
    print("\n" + "=" * 70)
    print("步骤2: 生成 challenge")
    print("=" * 70)
    
    # 模拟订单ID
    order_id = 12345678
    
    print(f"订单ID: {order_id}")
    print("调用: geetest_helper.generate_challenge(str(order_id))")
    
    challenge = geetest_helper.generate_challenge(str(order_id))
    
    print(f"✅ Challenge 生成成功")
    print(f"   Challenge: {challenge}")
    
    # 步骤3: 调用 verify 方法（和 APP 一样）
    print("\n" + "=" * 70)
    print("步骤3: 执行验证流程")
    print("=" * 70)
    
    print("调用: geetest_helper.verify(challenge=challenge)")
    print("这会自动完成:")
    print("  - Load (获取验证码图片)")
    print("  - 识别 (调用远程 AI)")
    print("  - 生成W参数")
    print("  - Verify (验证)")
    print()
    print("正在执行...")
    
    geetest_result = geetest_helper.verify(challenge=challenge)
    
    if not geetest_result or not geetest_result.get('success'):
        print(f"\n❌ 验证失败")
        if geetest_result:
            print(f"   错误: {geetest_result.get('error')}")
        sys.exit(1)
    
    print(f"\n✅ 验证成功！")
    print(f"   识别答案: {geetest_result.get('answers', [])}")
    
    # 步骤4: 构建 geeDto（和 APP 一样）
    print("\n" + "=" * 70)
    print("步骤4: 构建 geeDto")
    print("=" * 70)
    
    gee_dto = {
        'lotNumber': geetest_result.get('lot_number'),
        'captchaOutput': geetest_result.get('captcha_output'),
        'passToken': geetest_result.get('pass_token'),
        'genTime': str(geetest_result.get('gen_time', int(time.time()))),
        'captchaId': '045e2c229998a88721e32a763bc0f7b8',
        'captchaKeyType': 'dlVerify'
    }
    
    # 移除None值
    gee_dto = {k: v for k, v in gee_dto.items() if v is not None}
    
    print("✅ geeDto 构建成功")
    print()
    import json
    print(json.dumps(gee_dto, ensure_ascii=False, indent=2))
    
    # 总结
    print("\n" + "=" * 70)
    print("🎉 测试成功！")
    print("=" * 70)
    print()
    print("✅ 完整流程验证通过:")
    print("   1. GeetestHelper 初始化 - 成功")
    print("   2. generate_challenge() - 成功")
    print("   3. verify() - 成功 (使用远程 AI)")
    print("   4. 构建 geeDto - 成功")
    print()
    print("🌐 远程 AI 工作正常!")
    print(f"   服务器: {os.environ['AI_SERVER_URL']}")
    print(f"   识别答案: {geetest_result.get('answers', [])}")
    print()
    print("=" * 70)
    print("💡 这就是 APP 中实际使用的完整流程")
    print("=" * 70)
    print()
    
except Exception as e:
    print(f"\n❌ 测试失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
