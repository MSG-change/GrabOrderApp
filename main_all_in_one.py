#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速抢单助手 - 完全自包含版本
适用于：没有电脑，但有 Root 手机的用户

功能：
1. 内置 Frida Server（自动启动）
2. 自动 Hook 目标应用
3. 自动获取 Token
4. 快速抢单（0.2-0.5秒）
5. 可视化界面
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
        Log.i('FastGrabOrder', message)
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
from kivy.uix.spinner import Spinner
from kivy.uix.popup import Popup
from kivy.clock import Clock, mainthread
from kivy.properties import StringProperty, BooleanProperty
from kivy.core.window import Window

# 导入业务逻辑
sys.path.insert(0, os.path.dirname(__file__))

try:
    from src.frida_manager import FridaManager
    FRIDA_MANAGER_AVAILABLE = True
except Exception as e:
    log_print(f"⚠️ Frida 管理器导入失败: {e}")
    FRIDA_MANAGER_AVAILABLE = False

try:
    from src.auto_hook_service import AutoHookService
    AUTO_HOOK_AVAILABLE = True
except Exception as e:
    log_print(f"⚠️ Auto Hook 服务导入失败: {e}")
    AUTO_HOOK_AVAILABLE = False

try:
    from src.fast_grab_service import FastGrabOrderService
    GRAB_SERVICE_AVAILABLE = True
except Exception as e:
    log_print(f"⚠️ 抢单服务导入失败: {e}")
    GRAB_SERVICE_AVAILABLE = False


class MainScreen(BoxLayout):
    """主界面"""
    
    frida_status = StringProperty("未启动")
    hook_status = StringProperty("未连接")
    token_status = StringProperty("未获取")
    grab_status = StringProperty("未启动")
    log_text = StringProperty("")
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        self.orientation = 'vertical'
        self.padding = 10
        self.spacing = 8
        
        # 日志缓冲
        self.log_buffer = []
        self.max_logs = 150
        
        # 服务
        self.frida_manager = None
        self.hook_service = None
        self.grab_service = None
        
        # 配置
        self.api_base_url = "https://dysh.dyswl.com"
        self.target_package = "com.dyswl.dysh"
        
        # 构建 UI
        self.build_ui()
        
        # 定时更新
        Clock.schedule_interval(self.update_ui, 0.5)
        
        self.add_log("🚀 快速抢单助手 - 纯手机版")
        self.add_log(f"📱 环境: {'Android' if ANDROID else 'PC'}")
        
        if not FRIDA_MANAGER_AVAILABLE:
            self.add_log("⚠️ Frida 管理器不可用")
        if not AUTO_HOOK_AVAILABLE:
            self.add_log("⚠️ Hook 服务不可用")
        if not GRAB_SERVICE_AVAILABLE:
            self.add_log("⚠️ 抢单服务不可用")
    
    def build_ui(self):
        """构建界面"""
        # 标题
        title = Label(
            text='⚡ 快速抢单助手',
            size_hint_y=0.07,
            font_size='22sp',
            bold=True
        )
        self.add_widget(title)
        
        # 状态显示区域
        status_box = BoxLayout(size_hint_y=0.16, orientation='vertical', spacing=3)
        
        # Frida 状态
        frida_box = BoxLayout(size_hint_y=0.25, spacing=5)
        frida_box.add_widget(Label(text='Frida:', size_hint_x=0.3, font_size='13sp'))
        self.frida_label = Label(
            text=self.frida_status,
            size_hint_x=0.7,
            font_size='13sp',
            color=(1, 0.5, 0, 1)
        )
        frida_box.add_widget(self.frida_label)
        status_box.add_widget(frida_box)
        
        # Hook 状态
        hook_box = BoxLayout(size_hint_y=0.25, spacing=5)
        hook_box.add_widget(Label(text='Hook:', size_hint_x=0.3, font_size='13sp'))
        self.hook_label = Label(
            text=self.hook_status,
            size_hint_x=0.7,
            font_size='13sp',
            color=(1, 0.5, 0, 1)
        )
        hook_box.add_widget(self.hook_label)
        status_box.add_widget(hook_box)
        
        # Token 状态
        token_box = BoxLayout(size_hint_y=0.25, spacing=5)
        token_box.add_widget(Label(text='Token:', size_hint_x=0.3, font_size='13sp'))
        self.token_label = Label(
            text=self.token_status,
            size_hint_x=0.7,
            font_size='13sp',
            color=(1, 0.5, 0, 1)
        )
        token_box.add_widget(self.token_label)
        status_box.add_widget(token_box)
        
        # 抢单状态
        grab_box = BoxLayout(size_hint_y=0.25, spacing=5)
        grab_box.add_widget(Label(text='抢单:', size_hint_x=0.3, font_size='13sp'))
        self.grab_label = Label(
            text=self.grab_status,
            size_hint_x=0.7,
            font_size='13sp',
            color=(1, 0.5, 0, 1)
        )
        grab_box.add_widget(self.grab_label)
        status_box.add_widget(grab_box)
        
        self.add_widget(status_box)
        
        # 配置区域
        config_box = BoxLayout(size_hint_y=0.14, spacing=5, orientation='vertical')
        
        # 目标应用
        app_box = BoxLayout(size_hint_y=0.33, spacing=5)
        app_box.add_widget(Label(text='目标应用:', size_hint_x=0.35, font_size='12sp'))
        self.package_input = TextInput(
            text=self.target_package,
            multiline=False,
            size_hint_x=0.65,
            font_size='11sp'
        )
        app_box.add_widget(self.package_input)
        config_box.add_widget(app_box)
        
        # 检查间隔
        interval_box = BoxLayout(size_hint_y=0.33, spacing=5)
        interval_box.add_widget(Label(text='检查间隔:', size_hint_x=0.35, font_size='12sp'))
        self.interval_spinner = Spinner(
            text='1秒',
            values=('0.5秒', '1秒', '2秒', '3秒'),
            size_hint_x=0.65,
            font_size='11sp'
        )
        interval_box.add_widget(self.interval_spinner)
        config_box.add_widget(interval_box)
        
        # 商品类别
        category_box = BoxLayout(size_hint_y=0.33, spacing=5)
        category_box.add_widget(Label(text='商品类别:', size_hint_x=0.35, font_size='12sp'))
        self.category_input = TextInput(
            text='2469',
            multiline=False,
            size_hint_x=0.65,
            font_size='11sp'
        )
        category_box.add_widget(self.category_input)
        config_box.add_widget(category_box)
        
        self.add_widget(config_box)
        
        # 控制按钮
        btn_box = BoxLayout(size_hint_y=0.11, spacing=10)
        
        self.start_btn = Button(
            text='🚀 启动抢单',
            background_color=(0, 0.7, 0, 1),
            font_size='14sp',
            on_press=self.start_all_services
        )
        btn_box.add_widget(self.start_btn)
        
        self.stop_btn = Button(
            text='⏹️ 停止',
            background_color=(0.7, 0, 0, 1),
            font_size='14sp',
            disabled=True,
            on_press=self.stop_all_services
        )
        btn_box.add_widget(self.stop_btn)
        
        self.add_widget(btn_box)
        
        # 日志显示
        self.add_widget(Label(text='运行日志:', size_hint_y=0.04, halign='left', font_size='12sp'))
        
        scroll = ScrollView(size_hint_y=0.48)
        self.log_display = Label(
            text='',
            size_hint_y=None,
            halign='left',
            valign='top',
            font_size='10sp',
            color=(0.8, 0.8, 0.8, 1)
        )
        self.log_display.bind(texture_size=self.log_display.setter('size'))
        scroll.add_widget(self.log_display)
        self.add_widget(scroll)
    
    def start_all_services(self, instance):
        """启动所有服务"""
        self.add_log("")
        self.add_log("=" * 50)
        self.add_log("🚀 开始启动服务...")
        self.add_log("=" * 50)
        
        # 禁用启动按钮
        self.start_btn.disabled = True
        
        # 在后台线程启动
        threading.Thread(target=self._start_services_background, daemon=True).start()
    
    def _start_services_background(self):
        """后台启动所有服务"""
        try:
            # 1. 启动 Frida Server
            self.add_log("")
            self.add_log("【步骤 1/4】启动 Frida Server")
            self.add_log("-" * 50)
            
            if not FRIDA_MANAGER_AVAILABLE:
                self.add_log("❌ Frida 管理器不可用")
                self._on_start_failed()
                return
            
            self.frida_manager = FridaManager(log_callback=self.add_log)
            
            if not self.frida_manager.start_frida_server():
                self.add_log("❌ Frida Server 启动失败")
                self._on_start_failed()
                return
            
            self.frida_status = "✅ 运行中"
            
            # 2. 启动 Hook 服务
            self.add_log("")
            self.add_log("【步骤 2/4】启动 Hook 服务")
            self.add_log("-" * 50)
            
            if not AUTO_HOOK_AVAILABLE:
                self.add_log("❌ Hook 服务不可用")
                self._on_start_failed()
                return
            
            target_package = self.package_input.text.strip() or self.target_package
            
            self.hook_service = AutoHookService(
                target_package=target_package,
                log_callback=self.add_log
            )
            
            self.hook_service.set_token_callback(self.on_token_captured)
            
            if not self.hook_service.start():
                self.add_log("❌ Hook 服务启动失败")
                self._on_start_failed()
                return
            
            self.hook_status = "🔄 连接中"
            
            # 3. 初始化抢单服务
            self.add_log("")
            self.add_log("【步骤 3/4】初始化抢单服务")
            self.add_log("-" * 50)
            
            if not GRAB_SERVICE_AVAILABLE:
                self.add_log("❌ 抢单服务不可用")
                self._on_start_failed()
                return
            
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
            
            # 4. 等待 Token
            self.add_log("")
            self.add_log("【步骤 4/4】等待获取 Token")
            self.add_log("-" * 50)
            self.add_log("⏳ 请在目标应用中进行操作")
            self.add_log("   例如：打开订单列表")
            
            self._on_start_success()
            
        except Exception as e:
            self.add_log(f"❌ 启动失败: {e}")
            import traceback
            self.add_log(traceback.format_exc()[:300])
            self._on_start_failed()
    
    @mainthread
    def _on_start_success(self):
        """启动成功"""
        self.stop_btn.disabled = False
    
    @mainthread
    def _on_start_failed(self):
        """启动失败"""
        self.start_btn.disabled = False
        self.stop_btn.disabled = True
    
    @mainthread
    def on_token_captured(self, token_data):
        """Token 捕获回调"""
        token = token_data.get('token', '')
        if not token:
            return
        
        self.add_log("")
        self.add_log("=" * 50)
        self.add_log("🎯 Token 已获取！")
        self.add_log("=" * 50)
        self.add_log(f"Token: {token[:30]}...")
        
        for key in ['club_id', 'role_id', 'tenant_id']:
            value = token_data.get(key)
            if value:
                self.add_log(f"{key}: {value}")
        
        self.add_log("=" * 50)
        
        self.token_status = f"✅ {token[:12]}..."
        self.hook_status = "✅ 已连接"
        
        # 更新抢单服务
        if self.grab_service:
            self.grab_service.update_token(token_data)
            
            # 启动抢单
            if not self.grab_service.running:
                self.add_log("")
                self.add_log("🚀 自动启动抢单服务...")
                self.grab_service.start()
                self.grab_status = "✅ 运行中"
    
    def stop_all_services(self, instance):
        """停止所有服务"""
        self.add_log("")
        self.add_log("=" * 50)
        self.add_log("⏹️ 停止所有服务...")
        self.add_log("=" * 50)
        
        if self.grab_service:
            self.grab_service.stop()
            self.grab_service = None
            self.grab_status = "已停止"
        
        if self.hook_service:
            self.hook_service.stop()
            self.hook_service = None
            self.hook_status = "未连接"
        
        if self.frida_manager:
            # 不停止 Frida Server（可能其他应用在用）
            self.frida_manager = None
        
        self.token_status = "未获取"
        
        self.start_btn.disabled = False
        self.stop_btn.disabled = True
        
        self.add_log("✅ 所有服务已停止")
    
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
        self.frida_label.text = self.frida_status
        self.hook_label.text = self.hook_status
        self.token_label.text = self.token_status
        self.grab_label.text = self.grab_status
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
    log_print("🚀 快速抢单助手 - 纯手机版")
    log_print("=" * 50)
    
    try:
        app = FastGrabOrderApp()
        app.run()
    except Exception as e:
        log_print(f"❌ 启动失败: {e}")
        import traceback
        log_print(traceback.format_exc())

