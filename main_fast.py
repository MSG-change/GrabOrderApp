#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速抢单助手 - Kivy Android 应用（Frida 版本）
功能：Frida 自动获取 Token + 快速抢单
"""

import os
import sys
import threading
from datetime import datetime

# Android 日志
try:
    from jnius import autoclass
    ANDROID = True
    
    def log_print(*args, **kwargs):
        message = ' '.join(str(arg) for arg in args)
        Log = autoclass('android.util.Log')
        Log.i('GrabOrder', message)
        try:
            print(*args, **kwargs)
        except:
            pass
except ImportError:
    ANDROID = False
    def log_print(*args, **kwargs):
        print(*args, **kwargs)

# Kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.spinner import Spinner
from kivy.clock import Clock, mainthread
from kivy.properties import StringProperty, BooleanProperty
from kivy.core.window import Window

# 导入业务逻辑
sys.path.insert(0, os.path.dirname(__file__))

try:
    from src.frida_service import FridaTokenServiceSimple
    FRIDA_SERVICE_AVAILABLE = True
except Exception as e:
    log_print(f"⚠️ Frida 服务导入失败: {e}")
    FRIDA_SERVICE_AVAILABLE = False

try:
    from src.fast_grab_service import FastGrabOrderService
    GRAB_SERVICE_AVAILABLE = True
except Exception as e:
    log_print(f"⚠️ 抢单服务导入失败: {e}")
    GRAB_SERVICE_AVAILABLE = False


class MainScreen(BoxLayout):
    """主界面"""
    
    status_text = StringProperty("就绪")
    log_text = StringProperty("")
    is_running = BooleanProperty(False)
    token_status = StringProperty("未获取")
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        self.orientation = 'vertical'
        self.padding = 10
        self.spacing = 10
        
        # 日志缓冲
        self.log_buffer = []
        self.max_logs = 100
        
        # 服务
        self.frida_service = None
        self.grab_service = None
        
        # API 配置
        self.api_base_url = "https://dysh.dyswl.com"
        
        # 构建 UI
        self.build_ui()
        
        # 定时更新
        Clock.schedule_interval(self.update_ui, 0.5)
        
        self.add_log("🚀 快速抢单助手已启动")
        self.add_log(f"📱 模式: {'Android' if ANDROID else 'PC'}")
        
        if not FRIDA_SERVICE_AVAILABLE:
            self.add_log("⚠️ Frida 服务不可用")
        if not GRAB_SERVICE_AVAILABLE:
            self.add_log("⚠️ 抢单服务不可用")
    
    def build_ui(self):
        """构建界面"""
        # 标题
        title = Label(
            text='⚡ 快速抢单助手',
            size_hint_y=0.08,
            font_size='24sp',
            bold=True
        )
        self.add_widget(title)
        
        # Token 状态
        token_box = BoxLayout(size_hint_y=0.08, spacing=10)
        token_box.add_widget(Label(text='Token:', size_hint_x=0.3))
        self.token_label = Label(
            text=self.token_status,
            size_hint_x=0.7,
            color=(1, 0.5, 0, 1)
        )
        token_box.add_widget(self.token_label)
        self.add_widget(token_box)
        
        # 状态显示
        status_box = BoxLayout(size_hint_y=0.08, spacing=10)
        status_box.add_widget(Label(text='状态:', size_hint_x=0.3))
        self.status_label = Label(
            text=self.status_text,
            size_hint_x=0.7,
            color=(0, 1, 0, 1)
        )
        status_box.add_widget(self.status_label)
        self.add_widget(status_box)
        
        # 配置区域
        config_box = BoxLayout(size_hint_y=0.12, spacing=5, orientation='vertical')
        
        # 检查间隔
        interval_box = BoxLayout(size_hint_y=0.5, spacing=5)
        interval_box.add_widget(Label(text='检查间隔:', size_hint_x=0.4))
        self.interval_spinner = Spinner(
            text='1秒',
            values=('0.5秒', '1秒', '2秒', '3秒'),
            size_hint_x=0.6
        )
        interval_box.add_widget(self.interval_spinner)
        config_box.add_widget(interval_box)
        
        # 商品类别
        category_box = BoxLayout(size_hint_y=0.5, spacing=5)
        category_box.add_widget(Label(text='商品类别:', size_hint_x=0.4))
        self.category_input = TextInput(
            text='2469',
            multiline=False,
            size_hint_x=0.6
        )
        category_box.add_widget(self.category_input)
        config_box.add_widget(category_box)
        
        self.add_widget(config_box)
        
        # 控制按钮
        btn_box = BoxLayout(size_hint_y=0.12, spacing=10)
        
        self.start_btn = Button(
            text='启动抢单',
            background_color=(0, 0.7, 0, 1),
            on_press=self.start_service
        )
        btn_box.add_widget(self.start_btn)
        
        self.stop_btn = Button(
            text='停止',
            background_color=(0.7, 0, 0, 1),
            disabled=True,
            on_press=self.stop_service
        )
        btn_box.add_widget(self.stop_btn)
        
        self.add_widget(btn_box)
        
        # 手动输入 Token 按钮
        manual_token_btn = Button(
            text='手动输入 Token',
            size_hint_y=0.08,
            background_color=(0, 0.5, 0.8, 1),
            on_press=self.show_manual_token_input
        )
        self.add_widget(manual_token_btn)
        
        # 日志显示
        self.add_widget(Label(text='运行日志:', size_hint_y=0.05, halign='left'))
        
        scroll = ScrollView(size_hint_y=0.49)
        self.log_display = Label(
            text='',
            size_hint_y=None,
            halign='left',
            valign='top',
            font_size='11sp',
            color=(0.8, 0.8, 0.8, 1)
        )
        self.log_display.bind(texture_size=self.log_display.setter('size'))
        scroll.add_widget(self.log_display)
        self.add_widget(scroll)
    
    def start_service(self, instance):
        """启动服务"""
        if not FRIDA_SERVICE_AVAILABLE or not GRAB_SERVICE_AVAILABLE:
            self.add_log("❌ 核心服务不可用，无法启动")
            return
        
        self.add_log("🚀 正在启动服务...")
        
        # 在后台线程启动
        threading.Thread(target=self._start_services_background, daemon=True).start()
    
    def _start_services_background(self):
        """后台启动服务"""
        try:
            # 1. 启动 Frida Token 服务
            self.add_log("🔧 启动 Token 监控...")
            self.frida_service = FridaTokenServiceSimple(log_callback=self.add_log)
            self.frida_service.set_token_callback(self.on_token_captured)
            
            success = self.frida_service.start()
            if not success:
                self.add_log("❌ Token 监控启动失败")
                return
            
            # 2. 初始化抢单服务
            self.add_log("🔧 初始化抢单服务...")
            self.grab_service = FastGrabOrderService(
                api_base_url=self.api_base_url,
                log_callback=self.add_log
            )
            
            # 设置参数
            interval_text = self.interval_spinner.text
            if '0.5' in interval_text:
                self.grab_service.check_interval = 0.5
            elif '1' in interval_text:
                self.grab_service.check_interval = 1
            elif '2' in interval_text:
                self.grab_service.check_interval = 2
            else:
                self.grab_service.check_interval = 3
            
            self.grab_service.category_id = self.category_input.text.strip() or '2469'
            
            # 检查是否已有 Token
            token_data = self.frida_service.get_token_data()
            if token_data.get('token'):
                self.add_log("✅ 使用现有 Token 启动")
                self.grab_service.update_token(token_data)
                self.grab_service.start()
                
                self.is_running = True
                self.update_button_state()
            else:
                self.add_log("⏳ 等待获取 Token...")
                self.add_log("   请在目标 APP 中进行操作（如打开订单列表）")
                self.is_running = True
                self.update_button_state()
        
        except Exception as e:
            self.add_log(f"❌ 启动失败: {e}")
            import traceback
            self.add_log(traceback.format_exc()[:200])
    
    @mainthread
    def on_token_captured(self, token_data):
        """Token 捕获回调"""
        token = token_data.get('token', '')
        if not token:
            return
        
        self.add_log(f"🎯 Token 已更新: {token[:20]}...")
        self.token_status = f"✅ {token[:15]}..."
        
        # 更新抢单服务
        if self.grab_service:
            self.grab_service.update_token(token_data)
            
            # 如果还未启动，现在启动
            if not self.grab_service.running:
                self.grab_service.start()
                self.add_log("✅ 抢单服务已自动启动")
    
    def stop_service(self, instance):
        """停止服务"""
        self.add_log("⏹️ 正在停止服务...")
        
        if self.grab_service:
            self.grab_service.stop()
            self.grab_service = None
        
        if self.frida_service:
            self.frida_service.stop()
            self.frida_service = None
        
        self.is_running = False
        self.update_button_state()
        self.token_status = "未获取"
        
        self.add_log("✅ 服务已停止")
    
    def show_manual_token_input(self, instance):
        """显示手动输入 Token 弹窗"""
        content = BoxLayout(orientation='vertical', spacing=10, padding=10)
        
        content.add_widget(Label(text='输入完整的 Token:', size_hint_y=None, height=30))
        
        token_input = TextInput(
            text='',
            multiline=False,
            size_hint_y=None,
            height=50
        )
        content.add_widget(token_input)
        
        content.add_widget(Label(text='Club ID:', size_hint_y=None, height=30))
        club_input = TextInput(text='', multiline=False, size_hint_y=None, height=40)
        content.add_widget(club_input)
        
        content.add_widget(Label(text='Role ID:', size_hint_y=None, height=30))
        role_input = TextInput(text='', multiline=False, size_hint_y=None, height=40)
        content.add_widget(role_input)
        
        content.add_widget(Label(text='Tenant ID:', size_hint_y=None, height=30))
        tenant_input = TextInput(text='', multiline=False, size_hint_y=None, height=40)
        content.add_widget(tenant_input)
        
        btn_box = BoxLayout(size_hint_y=None, height=50, spacing=10)
        
        def save_manual_token(btn):
            token = token_input.text.strip().replace('Bearer ', '')
            if not token:
                self.add_log("❌ Token 不能为空")
                return
            
            token_data = {
                'token': token,
                'club_id': club_input.text.strip(),
                'role_id': role_input.text.strip(),
                'tenant_id': tenant_input.text.strip(),
            }
            
            self.on_token_captured(token_data)
            popup.dismiss()
        
        btn_box.add_widget(Button(text='保存', on_press=save_manual_token))
        btn_box.add_widget(Button(text='取消', on_press=lambda x: popup.dismiss()))
        
        content.add_widget(btn_box)
        
        popup = Popup(
            title='手动输入 Token',
            content=content,
            size_hint=(0.9, 0.8),
            auto_dismiss=False
        )
        popup.open()
    
    @mainthread
    def update_button_state(self):
        """更新按钮状态"""
        self.start_btn.disabled = self.is_running
        self.stop_btn.disabled = not self.is_running
        
        if self.is_running:
            self.status_text = "运行中"
            self.status_label.color = (0, 1, 0, 1)
        else:
            self.status_text = "已停止"
            self.status_label.color = (1, 0, 0, 1)
    
    @mainthread
    def add_log(self, message):
        """添加日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_line = f"[{timestamp}] {message}"
        
        self.log_buffer.append(log_line)
        if len(self.log_buffer) > self.max_logs:
            self.log_buffer.pop(0)
        
        self.log_text = '\n'.join(self.log_buffer)
    
    def update_ui(self, dt):
        """更新 UI"""
        self.status_label.text = self.status_text
        self.token_label.text = self.token_status
        self.log_display.text = self.log_text


class FastGrabOrderApp(App):
    """主应用"""
    
    def build(self):
        Window.clearcolor = (0.1, 0.1, 0.1, 1)
        
        # Android 权限
        if ANDROID:
            Clock.schedule_once(self.request_permissions, 0.5)
        
        return MainScreen()
    
    def request_permissions(self, dt):
        """请求权限"""
        try:
            from android.permissions import request_permissions, Permission
            permissions = [
                Permission.INTERNET,
                Permission.ACCESS_NETWORK_STATE,
                Permission.WRITE_EXTERNAL_STORAGE,
                Permission.READ_EXTERNAL_STORAGE,
            ]
            request_permissions(permissions)
        except Exception as e:
            log_print(f"权限请求失败: {e}")
    
    def on_pause(self):
        return True
    
    def on_resume(self):
        pass


if __name__ == '__main__':
    log_print("=" * 50)
    log_print("🚀 快速抢单助手启动")
    log_print("=" * 50)
    
    try:
        app = FastGrabOrderApp()
        app.run()
    except Exception as e:
        log_print(f"❌ 启动失败: {e}")
        import traceback
        log_print(traceback.format_exc())

