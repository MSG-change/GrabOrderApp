#!/usr/bin/env python3
"""
测试导入问题
"""
import sys
import os

# 添加路径
sys.path.insert(0, os.path.dirname(__file__))

print("=" * 60)
print("测试导入...")
print("=" * 60)

# 测试 fast_grab_service
print("\n1. 测试 FastGrabOrderService...")
try:
    from src.fast_grab_service import FastGrabOrderService
    print("✅ FastGrabOrderService 导入成功")
except Exception as e:
    print(f"❌ FastGrabOrderService 导入失败:")
    print(f"   错误: {e}")
    import traceback
    traceback.print_exc()

# 测试 geetest_helper_local
print("\n2. 测试 GeetestHelperLocal...")
try:
    from libs.geetest_helper_local import GeetestHelperLocal
    print("✅ GeetestHelperLocal 导入成功")
except Exception as e:
    print(f"❌ GeetestHelperLocal 导入失败:")
    print(f"   错误: {e}")
    import traceback
    traceback.print_exc()

# 测试 w_generator
print("\n3. 测试 W Generator...")
try:
    from libs.local_w_generator import LocalWGenerator
    print("✅ LocalWGenerator 导入成功")
except Exception as e:
    print(f"❌ LocalWGenerator 导入失败:")
    print(f"   错误: {e}")
    import traceback
    traceback.print_exc()

# 测试 android_w_generator
print("\n4. 测试 Android W Generator...")
try:
    from libs.android_w_generator import AndroidWGenerator
    print("✅ AndroidWGenerator 导入成功")
except Exception as e:
    print(f"⚠️ AndroidWGenerator 导入失败（PC环境正常）:")
    print(f"   错误: {e}")

print("\n" + "=" * 60)
print("测试完成")
print("=" * 60)
