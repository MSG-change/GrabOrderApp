#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
抢单助手 - 简化测试版本
用于调试黑屏问题
"""

import os
import sys

# Android日志输出
try:
    from jnius import autoclass
    ANDROID_LOG = True
    
    def log_print(*args, **kwargs):
        """输出日志到Android logcat"""
        Log = autoclass('android.util.Log')
        message = ' '.join(str(arg) for arg in args)
        Log.i('GrabOrder', message)
        # 同时尝试标准输出
        try:
            print(*args, **kwargs, file=sys.stdout)
            sys.stdout.flush()
        except:
            pass
except ImportError:
    ANDROID_LOG = False
    def log_print(*args, **kwargs):
        print(*args, **kwargs)

# Kivy 核心
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.core.window import Window

log_print("=" * 50)
log_print("🚀 简化测试版本启动")
log_print("=" * 50)

class SimpleScreen(BoxLayout):
    """最简单的测试界面"""
    
    def __init__(self, **kwargs):
        log_print("🔧 SimpleScreen.__init__ 开始")
        
        try:
            super().__init__(**kwargs)
            log_print("✅ super().__init__ 完成")
        except Exception as e:
            log_print(f"❌ super().__init__ 失败: {e}")
            import traceback
            log_print(traceback.format_exc())
            raise
        
        try:
            self.orientation = 'vertical'
            self.padding = 20
            self.spacing = 10
            log_print("✅ 基础属性设置完成")
        except Exception as e:
            log_print(f"❌ 基础属性设置失败: {e}")
        
        try:
            # 添加标题
            title = Label(
                text='测试界面',
                size_hint_y=0.2,
                font_size='30sp',
                color=(1, 1, 1, 1)
            )
            self.add_widget(title)
            log_print("✅ 标题添加完成")
            
            # 添加状态文本
            status = Label(
                text='如果您看到这个，说明UI正常显示！',
                size_hint_y=0.3,
                font_size='20sp',
                color=(0, 1, 0, 1)
            )
            self.add_widget(status)
            log_print("✅ 状态文本添加完成")
            
            # 添加测试按钮
            btn = Button(
                text='点击测试',
                size_hint_y=0.2,
                background_color=(0, 0.7, 0, 1),
                on_press=self.on_button_click
            )
            self.add_widget(btn)
            log_print("✅ 按钮添加完成")
            
            # 添加日志显示
            log_label = Label(
                text='日志区域\n请查看logcat',
                size_hint_y=0.3,
                font_size='14sp',
                color=(0.8, 0.8, 0.8, 1),
                halign='left',
                valign='top'
            )
            self.add_widget(log_label)
            log_print("✅ 日志区域添加完成")
            
            log_print("✅ 所有UI组件添加完成")
            
        except Exception as e:
            log_print(f"❌ UI组件添加失败: {e}")
            import traceback
            log_print(traceback.format_exc())
            # 即使失败，也添加一个错误显示
            try:
                error_label = Label(
                    text=f'错误: {e}',
                    color=(1, 0, 0, 1)
                )
                self.add_widget(error_label)
            except:
                pass
        
        log_print("✅ SimpleScreen.__init__ 完成")
    
    def on_button_click(self, instance):
        log_print("🔘 按钮被点击了！")


class SimpleApp(App):
    """简化测试应用"""
    
    def build(self):
        log_print("=" * 50)
        log_print("🔧 SimpleApp.build() 开始")
        log_print("=" * 50)
        
        try:
            log_print("🔧 设置窗口颜色...")
            Window.clearcolor = (0.1, 0.1, 0.1, 1)
            log_print("✅ 窗口颜色设置完成")
        except Exception as e:
            log_print(f"❌ 窗口颜色设置失败: {e}")
        
        try:
            log_print("🔧 创建SimpleScreen...")
            screen = SimpleScreen()
            log_print("✅ SimpleScreen创建完成")
            log_print("=" * 50)
            log_print("🎉 SimpleApp.build() 完成")
            log_print("=" * 50)
            return screen
        except Exception as e:
            log_print(f"❌ SimpleScreen创建失败: {e}")
            import traceback
            log_print(traceback.format_exc())
            # 返回一个最简单的Label
            try:
                error_label = Label(
                    text=f'启动失败:\n{e}\n\n请查看logcat',
                    color=(1, 0, 0, 1),
                    text_size=(Window.width - 40, None) if hasattr(Window, 'width') else None
                )
                return error_label
            except:
                return Label(text='严重错误', color=(1, 0, 0, 1))


if __name__ == '__main__':
    log_print("=" * 50)
    log_print("🚀 简化测试版本启动")
    log_print("=" * 50)
    log_print(f"Python版本: {sys.version}")
    log_print(f"工作目录: {os.getcwd()}")
    log_print(f"Android日志: {ANDROID_LOG}")
    log_print("=" * 50)
    
    try:
        app = SimpleApp()
        log_print("✅ SimpleApp实例创建成功")
        log_print("🔧 开始运行应用...")
        app.run()
    except Exception as e:
        log_print("=" * 50)
        log_print("❌ 应用启动失败！")
        log_print("=" * 50)
        log_print(f"错误: {e}")
        import traceback
        log_print(traceback.format_exc())
        log_print("=" * 50)

