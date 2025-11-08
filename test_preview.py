#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速预览测试脚本
检查所有依赖是否已安装
"""

import sys

print("🔍 检查依赖...")
print("=" * 50)

# 检查Python版本
print(f"✅ Python版本: {sys.version}")

# 检查Kivy
try:
    import kivy
    print(f"✅ Kivy版本: {kivy.__version__}")
except ImportError:
    print("❌ Kivy未安装")
    print("   安装命令: pip3 install kivy")
    sys.exit(1)

# 检查其他依赖
dependencies = {
    'kivy.uix': 'Kivy UI组件',
    'kivy.app': 'Kivy应用',
    'kivy.core.window': 'Kivy窗口',
    'PIL': 'Pillow (图像处理)',
    'requests': 'Requests (HTTP请求)',
}

missing = []
for module, name in dependencies.items():
    try:
        __import__(module)
        print(f"✅ {name}")
    except ImportError:
        print(f"❌ {name} 未安装")
        missing.append(module)

if missing:
    print("\n⚠️ 缺少依赖，安装命令:")
    if 'kivy' in str(missing):
        print("   pip3 install kivy pillow")
    if 'requests' in missing:
        print("   pip3 install requests")
    sys.exit(1)

print("\n" + "=" * 50)
print("✅ 所有依赖已安装！")
print("=" * 50)
print("\n🚀 可以开始预览了:")
print("   python3 main.py")
print("   或")
print("   ./preview_pc.sh")
print()

