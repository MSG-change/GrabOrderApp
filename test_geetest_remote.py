#!/usr/bin/env python3
"""
测试Geetest九宫格识别 - 使用远程AI服务
"""

import sys
import os
import time

# 添加路径
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'libs'))

from libs.geetest_helper_local import GeetestHelperLocal

def test_geetest_recognition():
    """测试Geetest九宫格识别"""
    
    print("="*70)
    print("🧪 Geetest九宫格识别测试 - 远程AI模式")
    print("="*70)
    print()
    
    # 检查环境变量
    ai_server_url = os.environ.get('AI_SERVER_URL')
    
    if ai_server_url:
        print(f"✅ 远程AI服务: {ai_server_url}")
    else:
        print("⚠️  未配置AI_SERVER_URL，将使用本地模式")
        print("   设置方法: export AI_SERVER_URL=http://192.168.31.232:8889")
    
    print()
    print("="*70)
    print("🔐 初始化Geetest助手...")
    print("="*70)
    print()
    
    # 创建Geetest助手
    captcha_id = "045e2c229998a88721e32a763bc0f7b8"
    helper = GeetestHelperLocal(captcha_id=captcha_id)
    
    print(f"📋 captcha_id: {captcha_id}")
    print()
    
    # 测试验证流程
    print("="*70)
    print("🚀 开始验证流程...")
    print("="*70)
    print()
    
    try:
        start_time = time.time()
        
        # 执行验证
        result = helper.verify()
        
        elapsed = (time.time() - start_time) * 1000
        
        if result and result.get('success'):
            print()
            print("="*70)
            print("✅ 验证成功！")
            print("="*70)
            print()
            print(f"⏱️  耗时: {elapsed:.0f}ms")
            print(f"🎯 识别结果: {result.get('answers', [])}")
            print(f"📦 lot_number: {result.get('lot_number', 'N/A')}")
            print(f"🔐 W参数: {result.get('captcha_output', 'N/A')[:50]}...")
            print(f"🎫 pass_token: {result.get('pass_token', 'N/A')[:50]}...")
            print()
            
            # 显示完整结果
            print("📊 完整结果:")
            for key, value in result.items():
                if key == 'captcha_output' and len(str(value)) > 50:
                    print(f"   {key}: {str(value)[:50]}...")
                elif key == 'pass_token' and len(str(value)) > 50:
                    print(f"   {key}: {str(value)[:50]}...")
                else:
                    print(f"   {key}: {value}")
            
            print()
            print("="*70)
            print("🎉 测试通过！")
            print("="*70)
            
        else:
            print()
            print("="*70)
            print("❌ 验证失败")
            print("="*70)
            print()
            if result:
                print(f"错误信息: {result}")
            else:
                print("未返回结果")
            print()
            
    except Exception as e:
        print()
        print("="*70)
        print("❌ 测试异常")
        print("="*70)
        print()
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()
        print()

def test_ai_server_health():
    """测试AI服务器健康状态"""
    import requests
    
    ai_server_url = os.environ.get('AI_SERVER_URL')
    if not ai_server_url:
        print("⚠️  未配置AI_SERVER_URL，跳过健康检查")
        return
    
    print("="*70)
    print("🏥 AI服务器健康检查")
    print("="*70)
    print()
    
    try:
        response = requests.get(f"{ai_server_url}/health", timeout=3)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ 服务器正常")
            print(f"   状态: {data.get('status')}")
            print(f"   准确率: {data.get('accuracy', 0)*100:.2f}%")
        else:
            print(f"❌ 服务器异常: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ 无法连接服务器: {e}")
    
    print()

if __name__ == '__main__':
    print()
    
    # 1. 健康检查
    test_ai_server_health()
    
    # 2. 识别测试
    test_geetest_recognition()
    
    print()
    print("="*70)
    print("📝 使用说明")
    print("="*70)
    print()
    print("1. 启动AI服务（Mac端）:")
    print("   python3 ai_server_simple.py 8889")
    print()
    print("2. 配置环境变量:")
    print("   export AI_SERVER_URL=http://192.168.31.232:8889")
    print()
    print("3. 运行测试:")
    print("   python3 test_geetest_remote.py")
    print()
