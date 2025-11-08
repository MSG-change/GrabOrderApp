#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试Kivy窗口显示
"""

from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.core.window import Window
from kivy.core.text import LabelBase
import sys
import os

print("=" * 50)
print("🔍 测试Kivy窗口")
print("=" * 50)

# 加载字体
font_name = None
try:
    font_paths = [
        'fonts/DroidSansFallback.ttf',
        './fonts/DroidSansFallback.ttf',
        os.path.join(os.path.dirname(__file__), 'fonts', 'DroidSansFallback.ttf'),
    ]
    for font_path in font_paths:
        if os.path.exists(font_path):
            try:
                LabelBase.register(
                    name='DroidSansFallback',
                    fn_regular=font_path
                )
                font_name = 'DroidSansFallback'
                print(f"✅ 字体加载成功: {font_path}")
                break
            except Exception as e:
                print(f"⚠️ 字体注册失败: {e}")
                continue
    if not font_name:
        print("⚠️ 未找到字体文件，将使用系统默认字体")
except Exception as e:
    print(f"⚠️ 字体加载失败: {e}")

# 设置窗口属性
try:
    Window.size = (400, 600)
    Window.clearcolor = (0.1, 0.1, 0.1, 1)
    print(f"✅ 窗口大小设置: {Window.size}")
    print(f"✅ 窗口位置: {Window.left}, {Window.top}")
except Exception as e:
    print(f"⚠️ 窗口设置失败: {e}")

# 字体参数
font_kwargs = {'font_name': font_name} if font_name else {}

class TestApp(App):
    def build(self):
        print("🔧 build() 被调用")
        
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)
        
        # 标题
        title = Label(
            text='测试窗口',
            font_size='30sp',
            color=(1, 1, 1, 1),
            size_hint_y=0.2,
            **font_kwargs
        )
        layout.add_widget(title)
        print("✅ 标题添加")
        
        # 状态
        status = Label(
            text='如果您看到这个窗口，说明Kivy正常工作！',
            font_size='20sp',
            color=(0, 1, 0, 1),
            size_hint_y=0.3,
            **font_kwargs
        )
        layout.add_widget(status)
        print("✅ 状态文本添加")
        
        # 按钮
        btn = Button(
            text='点击测试',
            size_hint_y=0.2,
            background_color=(0, 0.7, 0, 1),
            on_press=self.on_button_click,
            **font_kwargs
        )
        layout.add_widget(btn)
        print("✅ 按钮添加")
        
        # 信息
        info = Label(
            text='窗口应该已经显示了！\n请检查是否有窗口弹出。',
            font_size='16sp',
            color=(0.8, 0.8, 0.8, 1),
            size_hint_y=0.3,
            **font_kwargs
        )
        layout.add_widget(info)
        print("✅ 信息文本添加")
        
        print("✅ build() 完成")
        print("=" * 50)
        print("🎉 窗口应该已经显示！")
        print("=" * 50)
        print("如果看不到窗口，请检查：")
        print("1. 是否在后台或最小化")
        print("2. 是否被其他窗口遮挡")
        print("3. 按 Cmd+Tab 切换应用")
        print("=" * 50)
        
        return layout
    
    def on_button_click(self, instance):
        print("🔘 按钮被点击了！")
        instance.text = "已点击！"

if __name__ == '__main__':
    print("🚀 启动测试应用...")
    try:
        app = TestApp()
        print("✅ 应用实例创建")
        print("🔧 调用 app.run()...")
        app.run()
        print("✅ app.run() 返回")
    except Exception as e:
        print(f"❌ 启动失败: {e}")
        import traceback
        print(traceback.format_exc())
        sys.exit(1)

