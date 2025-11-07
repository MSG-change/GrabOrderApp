#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
抢单助手 - Kivy Android 应用
功能：VPN抓包 + 自动抢单 + Geetest识别
"""

import os
import sys
import threading
import logging
from datetime import datetime

# Kivy 核心
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.switch import Switch
from kivy.clock import Clock, mainthread
from kivy.properties import StringProperty, BooleanProperty
from kivy.core.window import Window

# Android 权限
try:
    from android.permissions import request_permissions, Permission
    from android import mActivity
    ANDROID = True
except ImportError:
    ANDROID = False

# 导入业务逻辑
sys.path.insert(0, os.path.dirname(__file__))
from src.vpn_service import VPNTokenCapture
from src.grab_service import GrabOrderService
from src.config_manager import ConfigManager


class MainScreen(BoxLayout):
    """主界面"""
    
    status_text = StringProperty("未启动")
    log_text = StringProperty("")
    is_running = BooleanProperty(False)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 20
        self.spacing = 10
        
        # 配置管理器
        self.config_mgr = ConfigManager()
        
        # VPN Token 捕获服务
        self.vpn_service = None
        
        # 抢单服务
        self.grab_service = None
        
        # 构建UI
        self.build_ui()
        
        # 日志缓冲
        self.log_buffer = []
        
        # 定时更新UI
        Clock.schedule_interval(self.update_ui, 0.5)
    
    def build_ui(self):
        """构建用户界面"""
        
        # 标题
        title = Label(
            text='🚀 抢单助手',
            size_hint_y=0.1,
            font_size='24sp',
            bold=True
        )
        self.add_widget(title)
        
        # 状态显示
        status_box = BoxLayout(size_hint_y=0.1, spacing=10)
        status_box.add_widget(Label(text='状态:', size_hint_x=0.3))
        self.status_label = Label(
            text=self.status_text,
            size_hint_x=0.7,
            color=(0, 1, 0, 1)
        )
        status_box.add_widget(self.status_label)
        self.add_widget(status_box)
        
        # Token 显示
        token_box = BoxLayout(size_hint_y=0.1, spacing=10)
        token_box.add_widget(Label(text='Token:', size_hint_x=0.3))
        self.token_label = Label(
            text='未获取',
            size_hint_x=0.7,
            color=(1, 1, 0, 1),
            font_size='10sp'
        )
        token_box.add_widget(self.token_label)
        self.add_widget(token_box)
        
        # 控制按钮
        btn_box = BoxLayout(size_hint_y=0.15, spacing=10)
        
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
        
        # VPN 抓包开关
        vpn_box = BoxLayout(size_hint_y=0.1, spacing=10)
        vpn_box.add_widget(Label(text='自动获取Token:', size_hint_x=0.6))
        self.vpn_switch = Switch(active=True, size_hint_x=0.4)
        self.vpn_switch.bind(active=self.toggle_vpn)
        vpn_box.add_widget(self.vpn_switch)
        self.add_widget(vpn_box)
        
        # 日志显示
        log_label = Label(
            text='运行日志:',
            size_hint_y=0.05,
            halign='left'
        )
        self.add_widget(log_label)
        
        scroll = ScrollView(size_hint_y=0.5)
        self.log_display = Label(
            text='',
            size_hint_y=None,
            halign='left',
            valign='top',
            font_size='12sp',
            color=(0.8, 0.8, 0.8, 1)
        )
        self.log_display.bind(texture_size=self.log_display.setter('size'))
        scroll.add_widget(self.log_display)
        self.add_widget(scroll)
    
    def start_service(self, instance):
        """启动服务"""
        self.add_log("🚀 正在启动服务...")
        
        # 检查配置
        config = self.config_mgr.get_config()
        if not config.get('phone'):
            self.add_log("❌ 请先在设置中配置手机号")
            return
        
        # 启动 VPN 抓包
        if self.vpn_switch.active:
            self.start_vpn()
        
        # 启动抢单服务
        threading.Thread(target=self._start_grab_service, daemon=True).start()
        
        # 更新UI
        self.is_running = True
        self.start_btn.disabled = True
        self.stop_btn.disabled = False
        self.status_text = "运行中"
        self.status_label.color = (0, 1, 0, 1)
    
    def _start_grab_service(self):
        """后台启动抢单服务"""
        try:
            config = self.config_mgr.get_config()
            
            self.grab_service = GrabOrderService(
                phone=config['phone'],
                api_base_url=config['api_base_url'],
                log_callback=self.add_log
            )
            
            self.add_log("✅ 抢单服务启动成功")
            self.grab_service.start()
            
        except Exception as e:
            self.add_log(f"❌ 启动失败: {e}")
            self.stop_service(None)
    
    def stop_service(self, instance):
        """停止服务"""
        self.add_log("⏹️ 正在停止服务...")
        
        # 停止抢单
        if self.grab_service:
            self.grab_service.stop()
            self.grab_service = None
        
        # 停止 VPN
        if self.vpn_service:
            self.vpn_service.stop()
            self.vpn_service = None
        
        # 更新UI
        self.is_running = False
        self.start_btn.disabled = False
        self.stop_btn.disabled = True
        self.status_text = "已停止"
        self.status_label.color = (1, 0, 0, 1)
        
        self.add_log("✅ 服务已停止")
    
    def start_vpn(self):
        """启动VPN抓包"""
        try:
            self.add_log("🔒 正在启动VPN抓包...")
            
            self.vpn_service = VPNTokenCapture(
                token_callback=self.on_token_captured,
                log_callback=self.add_log
            )
            
            if ANDROID:
                # Android 上启动 VPN Service
                self.vpn_service.start_vpn()
            else:
                # PC 上模拟
                self.add_log("⚠️ PC模式，VPN抓包已禁用")
        
        except Exception as e:
            self.add_log(f"❌ VPN启动失败: {e}")
    
    def toggle_vpn(self, instance, value):
        """切换VPN抓包"""
        if value:
            self.add_log("✅ VPN自动抓包已启用")
        else:
            self.add_log("⚠️ VPN自动抓包已禁用")
            if self.vpn_service:
                self.vpn_service.stop()
    
    @mainthread
    def on_token_captured(self, token, headers):
        """Token捕获回调"""
        self.add_log(f"🎯 捕获到新Token: {token[:20]}...")
        
        # 更新显示
        self.token_label.text = f"{token[:30]}..."
        
        # 保存到配置
        self.config_mgr.update_token(token, headers)
        
        # 更新抢单服务
        if self.grab_service:
            self.grab_service.update_token(token, headers)
    
    @mainthread
    def add_log(self, message):
        """添加日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_line = f"[{timestamp}] {message}"
        
        self.log_buffer.append(log_line)
        if len(self.log_buffer) > 100:
            self.log_buffer.pop(0)
        
        self.log_text = '\n'.join(self.log_buffer)
    
    def update_ui(self, dt):
        """定时更新UI"""
        self.status_label.text = self.status_text
        self.log_display.text = self.log_text


class GrabOrderApp(App):
    """主应用"""
    
    def build(self):
        """构建应用"""
        Window.clearcolor = (0.1, 0.1, 0.1, 1)
        
        # 请求权限
        if ANDROID:
            self.request_android_permissions()
        
        return MainScreen()
    
    def request_android_permissions(self):
        """请求Android权限"""
        permissions = [
            Permission.INTERNET,
            Permission.ACCESS_NETWORK_STATE,
            Permission.WRITE_EXTERNAL_STORAGE,
            Permission.READ_EXTERNAL_STORAGE,
            Permission.SYSTEM_ALERT_WINDOW,  # 悬浮窗
            Permission.FOREGROUND_SERVICE,    # 前台服务
        ]
        request_permissions(permissions)
    
    def on_pause(self):
        """应用暂停（保持后台运行）"""
        return True
    
    def on_resume(self):
        """应用恢复"""
        pass


if __name__ == '__main__':
    GrabOrderApp().run()

