#!/usr/bin/env python3
"""
直接测试远程 AI API
使用真实的验证码图片URL
"""
import requests
import json
import sys

AI_SERVER_URL = "http://154.219.127.13:8889"

def test_health():
    """测试健康检查"""
    print("=" * 70)
    print("1️⃣  测试 AI 服务器健康检查")
    print("=" * 70)
    
    try:
        response = requests.get(f"{AI_SERVER_URL}/health", timeout=5)
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


def test_recognize_api(question_url, grid_url):
    """测试识别 API"""
    print("\n" + "=" * 70)
    print("2️⃣  测试 AI 识别 API")
    print("=" * 70)
    
    print(f"问题图片: {question_url[:80]}...")
    print(f"九宫格图片: {grid_url[:80]}...")
    
    api_url = f"{AI_SERVER_URL}/api/recognize"
    
    data = {
        "question_url": question_url,
        "grid_url": grid_url,
        "threshold": 0.5
    }
    
    print(f"\n发送请求到: {api_url}")
    print("请求数据:")
    print(json.dumps(data, ensure_ascii=False, indent=2))
    
    try:
        response = requests.post(
            api_url,
            json=data,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        print(f"\n响应状态码: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("\n✅ 识别成功！")
            print(json.dumps(result, ensure_ascii=False, indent=2))
            
            if result.get('success'):
                answers = result.get('answers', [])
                predictions = result.get('predictions', [])
                
                print(f"\n🎯 识别结果:")
                print(f"   答案索引: {answers}")
                print(f"\n   详细得分:")
                for pred in predictions:
                    marker = "✓" if pred['index'] in answers else " "
                    print(f"     [{marker}] 格子 {pred['index']}: {pred['score']:.4f}")
                
                return True, answers
            else:
                print(f"\n❌ 识别失败: {result.get('error')}")
                return False, None
        else:
            print(f"\n❌ API 响应异常")
            print(response.text)
            return False, None
            
    except Exception as e:
        print(f"\n❌ 请求异常: {e}")
        import traceback
        traceback.print_exc()
        return False, None


def main():
    """主函数"""
    print("\n" + "🤖 " * 30)
    print("远程 AI API 测试")
    print("🤖 " * 30)
    print(f"\nAI 服务器: {AI_SERVER_URL}\n")
    
    # 测试1: 健康检查
    if not test_health():
        print("\n❌ 健康检查失败，终止测试")
        return
    
    # 测试2: 使用示例图片URL测试识别
    print("\n" + "=" * 70)
    print("提示: 需要真实的验证码图片URL才能测试识别功能")
    print("=" * 70)
    
    # 如果有命令行参数，使用它们
    if len(sys.argv) >= 3:
        question_url = sys.argv[1]
        grid_url = sys.argv[2]
        
        success, answers = test_recognize_api(question_url, grid_url)
        
        print("\n" + "=" * 70)
        print("📊 测试总结")
        print("=" * 70)
        print(f"✅ 健康检查: 通过")
        print(f"{'✅' if success else '❌'} AI识别: {'通过' if success else '失败'}")
        
        if success:
            print(f"\n🎉 远程 AI API 工作正常！")
            print(f"识别答案: {answers}")
        
        print("=" * 70 + "\n")
    else:
        print("\n使用方法:")
        print(f"  python {sys.argv[0]} <问题图片URL> <九宫格图片URL>")
        print("\n示例:")
        print(f"  python {sys.argv[0]} \\")
        print(f"    'https://static.geetest.com/pictures/gt/question.jpg' \\")
        print(f"    'https://static.geetest.com/pictures/gt/grid.jpg'")
        print("\n或者从实际登录流程中获取图片URL:")
        print("  1. 运行: python test_login_api.sh 13800138000")
        print("  2. 查看日志获取图片URL")
        print("  3. 使用获取的URL测试此脚本")
        print("")


if __name__ == '__main__':
    main()
