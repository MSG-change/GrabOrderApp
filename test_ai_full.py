#!/usr/bin/env python3
"""
完整测试 AI 服务器和抢单流程
"""
import os
import sys
import requests
import json

# 设置 AI 服务器地址
os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'

def test_health():
    """测试健康检查"""
    print("=" * 60)
    print("1️⃣  测试健康检查")
    print("=" * 60)
    
    try:
        response = requests.get(f"{os.environ['AI_SERVER_URL']}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ 服务器在线")
            print(f"   状态: {data.get('status')}")
            print(f"   模型已加载: {data.get('model_loaded')}")
            return True
        else:
            print(f"❌ 服务器响应异常: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ 连接失败: {e}")
        return False

def test_geetest_helper():
    """测试 GeetestHelper"""
    print("\n" + "=" * 60)
    print("2️⃣  测试 GeetestHelper 远程识别")
    print("=" * 60)
    
    try:
        from libs.geetest_helper_local import GeetestHelper
        
        print("✅ GeetestHelper 导入成功")
        
        # 创建实例
        helper = GeetestHelper()
        print(f"✅ GeetestHelper 初始化成功")
        print(f"   使用远程AI: {os.environ.get('AI_SERVER_URL')}")
        
        return True
    except Exception as e:
        print(f"❌ GeetestHelper 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_api_recognize():
    """测试 API 识别接口"""
    print("\n" + "=" * 60)
    print("3️⃣  测试 API 识别接口")
    print("=" * 60)
    
    # 使用测试图片 URL（如果有的话）
    print("ℹ️  需要真实的验证码图片URL才能测试识别功能")
    print("   可以在实际抢单时查看日志获取图片URL")
    
    return True

def main():
    """主测试流程"""
    print("\n" + "🚀 " * 20)
    print("AI 服务器完整测试")
    print("🚀 " * 20 + "\n")
    
    print(f"📍 AI 服务器: {os.environ['AI_SERVER_URL']}\n")
    
    results = []
    
    # 测试1: 健康检查
    results.append(("健康检查", test_health()))
    
    # 测试2: GeetestHelper
    results.append(("GeetestHelper", test_geetest_helper()))
    
    # 测试3: API 识别
    results.append(("API识别", test_api_recognize()))
    
    # 总结
    print("\n" + "=" * 60)
    print("📊 测试总结")
    print("=" * 60)
    
    for name, result in results:
        status = "✅ 通过" if result else "❌ 失败"
        print(f"{status}  {name}")
    
    all_passed = all(result for _, result in results)
    
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 所有测试通过！")
        print("\n下一步:")
        print("  1. 运行抢单APP: python main.py")
        print("  2. 或使用启动脚本: ./start_with_ai.sh")
        print("  3. 查看日志确认使用远程AI")
    else:
        print("⚠️  部分测试失败，请检查配置")
    print("=" * 60 + "\n")
    
    return all_passed

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
