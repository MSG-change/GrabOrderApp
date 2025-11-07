#!/usr/bin/env python3
"""
python-for-android 构建钩子
在编译前修复libffi等依赖问题
"""

import os
import subprocess
import sys


def pre_build_hook(ctx):
    """构建前钩子"""
    print("=" * 70)
    print("🔧 执行自定义构建钩子...")
    print("=" * 70)
    
    # 设置环境变量以修复autoconf问题
    os.environ['ACLOCAL_PATH'] = '/usr/share/aclocal'
    os.environ['PKG_CONFIG_PATH'] = '/usr/lib/pkgconfig:/usr/share/pkgconfig'
    
    # 输出环境信息
    print("✅ 环境变量已设置:")
    print(f"   ACLOCAL_PATH: {os.environ.get('ACLOCAL_PATH')}")
    print(f"   PKG_CONFIG_PATH: {os.environ.get('PKG_CONFIG_PATH')}")
    
    return True


def post_build_hook(ctx):
    """构建后钩子"""
    print("=" * 70)
    print("✅ 构建完成")
    print("=" * 70)
    return True

