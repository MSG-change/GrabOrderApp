#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试Mac系统字体加载
"""

import os
import platform
from kivy.core.text import LabelBase
from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.core.window import Window

print("=" * 50)
print("🔍 测试Mac系统字体加载")
print("=" * 50)

# Mac系统字体路径
mac_font_paths = [
    '/System/Library/Fonts/STHeiti Light.ttc',
    '/System/Library/Fonts/STHeiti Medium.ttc',
    '/System/Library/Fonts/CJKSymbolsFallback.ttc',
    '/Library/Fonts/Arial Unicode.ttf',
]

print("\n📋 检查字体文件是否存在：")
for font_path in mac_font_paths:
    exists = os.path.exists(font_path)
    size = os.path.getsize(font_path) if exists else 0
    print(f"  {'✅' if exists else '❌'} {font_path} ({size/1024/1024:.1f}MB)")

print("\n🔧 尝试注册字体：")
font_loaded = False
for font_path in mac_font_paths:
    if os.path.exists(font_path):
        try:
            print(f"  尝试: {font_path}")
            LabelBase.register(
                name='TestFont',
                fn_regular=font_path
            )
            print(f"  ✅ 字体注册成功: {font_path}")
            font_loaded = True
            break
        except Exception as e:
            print(f"  ❌ 字体注册失败: {e}")
            continue

if not font_loaded:
    print("\n⚠️ 所有系统字体注册失败")
    print("   尝试项目字体...")
    project_font = 'fonts/DroidSansFallback.ttf'
    if os.path.exists(project_font):
        try:
            abs_path = os.path.abspath(project_font)
            LabelBase.register(
                name='TestFont',
                fn_regular=abs_path
            )
            print(f"  ✅ 项目字体注册成功: {abs_path}")
            font_loaded = True
        except Exception as e:
            print(f"  ❌ 项目字体注册失败: {e}")

print("\n" + "=" * 50)
print("🧪 测试字体显示")
print("=" * 50)

class TestApp(App):
    def build(self):
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)
        
        if font_loaded:
            test_label = Label(
                text='测试中文显示：抢单助手\n如果看到这行中文，字体加载成功！',
                font_size='24sp',
                font_name='TestFont',
                color=(0, 1, 0, 1)
            )
            layout.add_widget(test_label)
            
            info_label = Label(
                text='✅ 字体加载成功！\n中文应该正常显示了。',
                font_size='16sp',
                color=(0.8, 0.8, 0.8, 1)
            )
        else:
            test_label = Label(
                text='测试中文显示：抢单助手\n如果看到方块，字体加载失败',
                font_size='24sp',
                color=(1, 0, 0, 1)
            )
            layout.add_widget(test_label)
            
            info_label = Label(
                text='❌ 字体加载失败\n使用系统默认字体（中文可能显示为方块）',
                font_size='16sp',
                color=(1, 0.5, 0, 1)
            )
        
        layout.add_widget(info_label)
        return layout

if __name__ == '__main__':
    TestApp().run()

