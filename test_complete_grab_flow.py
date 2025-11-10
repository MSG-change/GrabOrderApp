#!/usr/bin/env python3
"""
完整抢单流程测试
模拟真实的抢单场景，验证所有步骤
"""
import os
import sys
import time
import json

# 设置远程 AI
os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'

from libs.geetest_helper_local import GeetestHelper

print("\n" + "🚀 " * 30)
print("完整抢单流程测试")
print("🚀 " * 30 + "\n")

# ============================================================================
# 模拟参数
# ============================================================================
CAPTCHA_ID = "045e2c229998a88721e32a763bc0f7b8"
ORDER_ID = 12345678  # 模拟订单ID

print("测试参数:")
print(f"  Captcha ID: {CAPTCHA_ID}")
print(f"  Order ID: {ORDER_ID}")
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
    print(f"   使用远程AI: {geetest_helper.model is None}")
except Exception as e:
    print(f"❌ 初始化失败: {e}")
    sys.exit(1)

# ============================================================================
# 步骤2: 生成 challenge（基于订单ID）
# ============================================================================
print("\n" + "=" * 70)
print("步骤2: 生成 challenge")
print("=" * 70)

try:
    challenge = geetest_helper.generate_challenge(str(ORDER_ID))
    print(f"✅ Challenge 生成成功")
    print(f"   Challenge: {challenge}")
except Exception as e:
    print(f"❌ Challenge 生成失败: {e}")
    sys.exit(1)

# ============================================================================
# 步骤3: 执行验证流程（Load → 识别 → 生成W → Verify）
# ============================================================================
print("\n" + "=" * 70)
print("步骤3: 执行验证流程")
print("=" * 70)

print("调用 geetest_helper.verify(challenge)")
print("这会自动完成:")
print("  1. 调用远程 AI 识别验证码")
print("  2. 获取 lot_number 和 pass_token")
print("  3. 生成 W 参数 (captcha_output)")
print("  4. 返回完整结果")
print()

start_time = time.time()

try:
    geetest_result = geetest_helper.verify(challenge=challenge)
    
    elapsed = time.time() - start_time
    
    if not geetest_result or not geetest_result.get('success'):
        print(f"❌ 验证失败")
        if geetest_result:
            print(f"   错误: {geetest_result.get('error')}")
        sys.exit(1)
    
    print(f"✅ 验证成功！(耗时: {elapsed:.2f}秒)")
    print(f"   识别答案: {geetest_result.get('answers', [])}")
    print(f"   Lot Number: {geetest_result.get('lot_number')}")
    print(f"   W 参数: {geetest_result.get('captcha_output')}")
    print(f"   Pass Token: {geetest_result.get('pass_token')[:50]}...")
    
except Exception as e:
    print(f"❌ 验证异常: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# ============================================================================
# 步骤4: 构建 geeDto（用于抢单请求）
# ============================================================================
print("\n" + "=" * 70)
print("步骤4: 构建 geeDto")
print("=" * 70)

try:
    gee_dto = {
        'lotNumber': geetest_result.get('lot_number'),
        'captchaOutput': geetest_result.get('captcha_output'),
        'passToken': geetest_result.get('pass_token'),
        'genTime': str(geetest_result.get('gen_time', int(time.time()))),
        'captchaId': CAPTCHA_ID,
        'captchaKeyType': 'dlVerify'
    }
    
    # 移除None值
    gee_dto = {k: v for k, v in gee_dto.items() if v is not None}
    
    print("✅ geeDto 构建成功")
    print()
    print(json.dumps(gee_dto, ensure_ascii=False, indent=2))
    
except Exception as e:
    print(f"❌ 构建失败: {e}")
    sys.exit(1)

# ============================================================================
# 步骤5: 验证 geeDto 完整性
# ============================================================================
print("\n" + "=" * 70)
print("步骤5: 验证 geeDto 完整性")
print("=" * 70)

required_fields = ['lotNumber', 'captchaOutput', 'passToken', 'genTime', 'captchaId', 'captchaKeyType']
missing_fields = []

for field in required_fields:
    if field not in gee_dto or not gee_dto[field]:
        missing_fields.append(field)
        print(f"❌ 缺少字段: {field}")
    else:
        print(f"✅ {field}: {str(gee_dto[field])[:50]}...")

if missing_fields:
    print(f"\n❌ geeDto 不完整，缺少字段: {missing_fields}")
    sys.exit(1)
else:
    print(f"\n✅ geeDto 完整，所有必需字段都存在")

# ============================================================================
# 步骤6: 模拟抢单请求
# ============================================================================
print("\n" + "=" * 70)
print("步骤6: 模拟抢单请求")
print("=" * 70)

print("在实际使用中，会这样发送抢单请求:")
print()
print("```python")
print("response = requests.post(")
print("    'https://app.shunshunxiaozhan.com/driver/order/grab',")
print("    json={")
print("        'orderId': order_id,")
print("        'geeDto': gee_dto")
print("    },")
print("    headers=headers")
print(")")
print("```")
print()
print("geeDto 内容:")
print(json.dumps(gee_dto, ensure_ascii=False, indent=2))

# ============================================================================
# 总结
# ============================================================================
print("\n" + "=" * 70)
print("🎉 测试总结")
print("=" * 70)

print(f"""
✅ 所有步骤测试通过！

测试结果:
  ✅ 步骤1: GeetestHelper 初始化成功
  ✅ 步骤2: Challenge 生成成功
  ✅ 步骤3: 验证流程完成 (耗时: {elapsed:.2f}秒)
  ✅ 步骤4: geeDto 构建成功
  ✅ 步骤5: geeDto 完整性验证通过
  ✅ 步骤6: 可以用于抢单请求

关键数据:
  - 识别答案: {geetest_result.get('answers', [])}
  - Lot Number: {geetest_result.get('lot_number')}
  - W 参数长度: {len(geetest_result.get('captcha_output', ''))} 字符
  - Pass Token 长度: {len(geetest_result.get('pass_token', ''))} 字符

🎯 结论: 完整流程正常，可以投入生产使用！
""")

print("=" * 70)
