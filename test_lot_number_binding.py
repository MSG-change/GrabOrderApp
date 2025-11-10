#!/usr/bin/env python3
"""
演示lot_number绑定机制
展示为什么必须使用同一个Load的数据
"""

import requests
import json
import uuid

def test_lot_number_binding():
    """测试lot_number绑定"""
    
    print("="*70)
    print("🔍 测试验证码唯一性和绑定机制")
    print("="*70)
    print()
    
    captcha_id = "045e2c229998a88721e32a763bc0f7b8"
    
    # ============================================================
    # 场景1: 第一次Load
    # ============================================================
    print("📋 场景1: 第一次Load")
    print("-"*70)
    
    challenge_1 = str(uuid.uuid4())
    print(f"Challenge 1: {challenge_1}")
    
    load_url = "http://gcaptcha4.geetest.com/load"
    load_params_1 = {
        'captcha_id': captcha_id,
        'challenge': challenge_1,
        'client_type': 'android',
        'lang': 'zh-cn'
    }
    
    response_1 = requests.get(load_url, params=load_params_1)
    text_1 = response_1.text
    if text_1.startswith('(') and text_1.endswith(')'):
        text_1 = text_1[1:-1]
    
    load_data_1 = json.loads(text_1)
    
    if load_data_1.get('status') == 'success':
        data_1 = load_data_1['data']
        lot_number_1 = data_1['lot_number']
        payload_1 = data_1['payload']
        process_token_1 = data_1['process_token']
        imgs_1 = data_1['imgs']
        ques_1 = data_1['ques'][0]
        
        print(f"✅ Load 1 成功")
        print(f"   lot_number: {lot_number_1}")
        print(f"   imgs: {imgs_1[:50]}...")
        print(f"   ques: {ques_1[:50]}...")
        print(f"   payload: {payload_1[:50]}...")
        print(f"   process_token: {process_token_1[:50]}...")
    else:
        print("❌ Load 1 失败")
        return
    
    print()
    
    # ============================================================
    # 场景2: 第二次Load（不同的challenge）
    # ============================================================
    print("📋 场景2: 第二次Load（不同的challenge）")
    print("-"*70)
    
    challenge_2 = str(uuid.uuid4())
    print(f"Challenge 2: {challenge_2}")
    
    load_params_2 = {
        'captcha_id': captcha_id,
        'challenge': challenge_2,  # ← 不同的challenge
        'client_type': 'android',
        'lang': 'zh-cn'
    }
    
    response_2 = requests.get(load_url, params=load_params_2)
    text_2 = response_2.text
    if text_2.startswith('(') and text_2.endswith(')'):
        text_2 = text_2[1:-1]
    
    load_data_2 = json.loads(text_2)
    
    if load_data_2.get('status') == 'success':
        data_2 = load_data_2['data']
        lot_number_2 = data_2['lot_number']
        payload_2 = data_2['payload']
        process_token_2 = data_2['process_token']
        imgs_2 = data_2['imgs']
        ques_2 = data_2['ques'][0]
        
        print(f"✅ Load 2 成功")
        print(f"   lot_number: {lot_number_2}")
        print(f"   imgs: {imgs_2[:50]}...")
        print(f"   ques: {ques_2[:50]}...")
        print(f"   payload: {payload_2[:50]}...")
        print(f"   process_token: {process_token_2[:50]}...")
    else:
        print("❌ Load 2 失败")
        return
    
    print()
    
    # ============================================================
    # 对比
    # ============================================================
    print("📋 对比两次Load的结果")
    print("-"*70)
    
    print(f"lot_number相同？ {lot_number_1 == lot_number_2}")
    if lot_number_1 != lot_number_2:
        print(f"   Load 1: {lot_number_1}")
        print(f"   Load 2: {lot_number_2}")
        print(f"   ✅ 每次Load都生成不同的lot_number")
    
    print()
    print(f"imgs相同？ {imgs_1 == imgs_2}")
    if imgs_1 != imgs_2:
        print(f"   ✅ 每次Load返回不同的九宫格图片")
    
    print()
    print(f"ques相同？ {ques_1 == ques_2}")
    if ques_1 != ques_2:
        print(f"   ✅ 每次Load返回不同的问题图片")
    
    print()
    print(f"payload相同？ {payload_1 == payload_2}")
    if payload_1 != payload_2:
        print(f"   ✅ payload与lot_number绑定")
    
    print()
    print(f"process_token相同？ {process_token_1 == process_token_2}")
    if process_token_1 != process_token_2:
        print(f"   ✅ process_token与lot_number绑定")
    
    print()
    
    # ============================================================
    # 关键结论
    # ============================================================
    print("="*70)
    print("🔑 关键结论")
    print("="*70)
    print()
    print("1. 每次Load都会生成：")
    print("   - 唯一的 lot_number")
    print("   - 不同的图片（imgs、ques）")
    print("   - 绑定的 payload 和 process_token")
    print()
    print("2. 这些数据必须配套使用：")
    print("   - lot_number_1 + payload_1 + process_token_1 ✅")
    print("   - lot_number_1 + payload_2 + process_token_1 ❌ 失败")
    print("   - lot_number_2 + payload_1 + process_token_2 ❌ 失败")
    print()
    print("3. APP传递数据的正确方式：")
    print("   方式A（推荐）：")
    print("     APP → AI: {captcha_id, challenge}")
    print("     AI服务器内部完成Load→识别→Verify")
    print("     AI → APP: {lot_number, captcha_output, pass_token, ...}")
    print("     ✅ AI服务器保证数据一致性")
    print()
    print("   方式B（不推荐）：")
    print("     APP自己Load，获取lot_number、imgs、ques")
    print("     APP → AI: {question_url, grid_url}")
    print("     AI → APP: {answers}")
    print("     APP自己生成W、调用Verify")
    print("     ❌ 容易出错，可能混用不同Load的数据")
    print()
    print("4. 为什么方式A更好：")
    print("   - ✅ 数据一致性由AI服务器保证")
    print("   - ✅ APP不需要管理lot_number")
    print("   - ✅ 不会出现超时问题")
    print("   - ✅ 代码更简单")
    print()
    
    # ============================================================
    # 实际代码示例
    # ============================================================
    print("="*70)
    print("💻 实际代码示例")
    print("="*70)
    print()
    
    print("# 当前实现（正确）")
    print("```python")
    print("def verify(self, challenge):")
    print("    # 步骤1: Load（获取lot_number和图片）")
    print("    load_data = load(captcha_id, challenge)")
    print("    lot_number = load_data['lot_number']")
    print("    payload = load_data['payload']")
    print("    process_token = load_data['process_token']")
    print("    ")
    print("    # 步骤2: 识别（使用这个验证码的图片）")
    print("    answers = recognize(load_data['imgs'], load_data['ques'])")
    print("    ")
    print("    # 步骤3: 生成W（使用这个验证码的lot_number）")
    print("    w = generate_w(lot_number, answers, ...)")
    print("    ")
    print("    # 步骤4: Verify（使用这个验证码的所有数据）")
    print("    result = verify(lot_number, payload, process_token, w)")
    print("    ")
    print("    # 步骤5: 返回（包含lot_number）")
    print("    return {")
    print("        'lot_number': lot_number,  # ← 返回给APP")
    print("        'captcha_output': w,")
    print("        'pass_token': result['pass_token'],")
    print("        ...")
    print("    }")
    print("```")
    print()

if __name__ == '__main__':
    test_lot_number_binding()
