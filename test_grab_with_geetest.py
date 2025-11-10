#!/usr/bin/env python3
"""
测试完整抢单流程（带Geetest验证）
模拟真实抢单场景
"""

import sys
import os
import time
import json

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'libs'))

from libs.geetest_helper_local import GeetestHelperLocal

def test_grab_flow():
    """测试完整抢单流程"""
    
    print("="*70)
    print("🎯 模拟完整抢单流程")
    print("="*70)
    print()
    
    # 模拟订单
    order_id = "3308987"
    
    # ============================================================
    # 步骤1: 第一次抢单请求（不带验证）
    # ============================================================
    print("📋 步骤1: 发送抢单请求（不带验证）")
    print(f"   POST /grabAnOrder/v1")
    print(f"   {{'orderId': '{order_id}'}}")
    print()
    
    # 模拟服务器返回需要验证
    print("📋 步骤2: 服务器返回需要验证")
    print(f"   {{'code': 1001, 'msg': '需要验证'}}")
    print()
    
    # ============================================================
    # 步骤3-7: Geetest验证流程
    # ============================================================
    print("="*70)
    print("🔐 开始Geetest验证流程")
    print("="*70)
    print()
    
    # 初始化Geetest助手
    captcha_id = "045e2c229998a88721e32a763bc0f7b8"
    helper = GeetestHelperLocal(captcha_id=captcha_id)
    
    # 生成challenge（基于订单ID）
    challenge = GeetestHelperLocal.generate_challenge(order_id)
    print(f"📋 步骤3: 生成challenge")
    print(f"   challenge: {challenge}")
    print()
    
    # 执行验证
    print(f"📋 步骤4-7: 执行Geetest验证")
    print(f"   4. Load - 获取验证码数据")
    print(f"   5. 识别九宫格")
    print(f"   6. 生成W参数")
    print(f"   7. Verify验证")
    print()
    
    start_time = time.time()
    result = helper.verify(challenge=challenge)
    elapsed = (time.time() - start_time) * 1000
    
    if not result or not result.get('success'):
        print("❌ 验证失败")
        return
    
    print(f"✅ 验证成功！耗时: {elapsed:.0f}ms")
    print()
    
    # ============================================================
    # 步骤8: 构建geeDto
    # ============================================================
    print("="*70)
    print("📋 步骤8: 构建geeDto（验证结果）")
    print("="*70)
    print()
    
    gee_dto = {
        'lotNumber': result.get('lot_number'),
        'captchaOutput': result.get('captcha_output'),
        'passToken': result.get('pass_token'),
        'genTime': str(result.get('gen_time', int(time.time()))),
        'captchaId': captcha_id,
        'captchaKeyType': 'dlVerify'
    }
    
    print("geeDto结构:")
    for key, value in gee_dto.items():
        if isinstance(value, str) and len(value) > 50:
            print(f"   {key}: {value[:50]}...")
        else:
            print(f"   {key}: {value}")
    print()
    
    # ============================================================
    # 步骤9: 第二次抢单请求（带验证）
    # ============================================================
    print("="*70)
    print("📋 步骤9: 重新发送抢单请求（带geeDto）")
    print("="*70)
    print()
    
    payload = {
        'orderId': order_id,
        'geeDto': gee_dto
    }
    
    print("完整请求体:")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print()
    
    # ============================================================
    # 步骤10: 模拟成功
    # ============================================================
    print("="*70)
    print("📋 步骤10: 服务器返回")
    print("="*70)
    print()
    print("✅ {'code': 0, 'msg': '抢单成功'}")
    print()
    
    # ============================================================
    # 总结
    # ============================================================
    print("="*70)
    print("🎉 完整流程测试完成！")
    print("="*70)
    print()
    print("📊 流程总结:")
    print("   1. ✅ 第一次请求（不带验证）→ code=1001")
    print("   2. ✅ Load获取验证码数据")
    print("   3. ✅ 识别九宫格 →", result.get('answers'))
    print("   4. ✅ 生成W参数")
    print("   5. ✅ Verify验证W参数")
    print("   6. ✅ 构建geeDto")
    print("   7. ✅ 第二次请求（带geeDto）→ code=0")
    print()
    print("🔑 关键点:")
    print("   - callback参数: ❌ 不需要（APP直接HTTP请求）")
    print("   - 验证结果携带: ✅ 通过geeDto对象")
    print("   - geeDto包含: lotNumber, captchaOutput, passToken, genTime")
    print()

if __name__ == '__main__':
    # 检查AI服务
    ai_server_url = os.environ.get('AI_SERVER_URL')
    if not ai_server_url:
        print("⚠️  未配置AI_SERVER_URL")
        print("   设置方法: export AI_SERVER_URL=http://127.0.0.1:8889")
        print()
    
    test_grab_flow()
