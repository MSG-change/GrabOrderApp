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

# Android日志输出
try:
    from jnius import autoclass
    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    ANDROID_LOG = True
    
    def android_log(level, tag, message):
        """输出日志到Android logcat"""
        Log = autoclass('android.util.Log')
        if level == 'd':
            Log.d(tag, message)
        elif level == 'i':
            Log.i(tag, message)
        elif level == 'w':
            Log.w(tag, message)
        elif level == 'e':
            Log.e(tag, message)
        else:
            Log.i(tag, message)
    
    def log_print(*args, **kwargs):
        """重定向print到Android日志"""
        message = ' '.join(str(arg) for arg in args)
        android_log('i', 'GrabOrder', message)
        # 同时输出到标准输出（如果可用）
        try:
            print(*args, **kwargs)
        except:
            pass
except ImportError:
    ANDROID_LOG = False
    def log_print(*args, **kwargs):
        print(*args, **kwargs)

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
from kivy.core.text import LabelBase

# Android 权限
try:
    from android.permissions import request_permissions, Permission
    from android import mActivity
    ANDROID = True
except ImportError:
    ANDROID = False

# 导入业务逻辑
sys.path.insert(0, os.path.dirname(__file__))

# 安全导入，避免启动崩溃
try:
    from src.vpn_service import VPNTokenCapture
except Exception as e:
    log_print(f"⚠️ VPN服务导入失败: {e}")
    VPNTokenCapture = None

try:
    from src.grab_service import GrabOrderService
except Exception as e:
    log_print(f"⚠️ 抢单服务导入失败: {e}")
    GrabOrderService = None

try:
    from src.config_manager import ConfigManager
except Exception as e:
    log_print(f"⚠️ 配置管理器导入失败: {e}")
    ConfigManager = None


class MainScreen(BoxLayout):
    """主界面"""
    
    status_text = StringProperty("未启动")
    log_text = StringProperty("")
    is_running = BooleanProperty(False)
    
    def __init__(self, **kwargs):
        log_print("=" * 50)
        log_print("🔧 MainScreen.__init__ 开始")
        log_print("=" * 50)
        
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
        
        # 先初始化日志缓冲（避免后续调用add_log时出错）
        self.log_buffer = []
        log_print("✅ 日志缓冲初始化完成")
        
        # 配置管理器（安全初始化）
        try:
            if ConfigManager:
                self.config_mgr = ConfigManager()
                log_print("✅ 配置管理器初始化成功")
            else:
                self.config_mgr = None
                log_print("⚠️ 配置管理器不可用")
        except Exception as e:
            log_print(f"❌ 配置管理器初始化失败: {e}")
            import traceback
            log_print(traceback.format_exc())
            self.config_mgr = None
        
        # VPN Token 捕获服务
        self.vpn_service = None
        
        # 抢单服务
        self.grab_service = None
        
        log_print("🔧 开始构建UI...")
        try:
            # 构建UI
            self.build_ui()
            log_print("✅ UI构建完成")
        except Exception as e:
            log_print(f"❌ UI构建失败: {e}")
            import traceback
            log_print(traceback.format_exc())
            # 即使UI构建失败，也创建一个最简单的显示
            self.add_widget(Label(text=f"UI构建失败: {e}", color=(1, 0, 0, 1)))
        
        log_print("🔧 设置定时更新...")
        try:
            # 定时更新UI
            Clock.schedule_interval(self.update_ui, 0.5)
            log_print("✅ 定时更新设置完成")
        except Exception as e:
            log_print(f"❌ 定时更新设置失败: {e}")
        
        # 启动日志（延迟到UI构建后）
        try:
            self.add_log("🚀 抢单助手已启动")
            self.add_log(f"📱 Android模式: {ANDROID}")
            if not ConfigManager:
                self.add_log("⚠️ 配置管理器加载失败")
            if not GrabOrderService:
                self.add_log("⚠️ 抢单服务加载失败")
            if not VPNTokenCapture:
                self.add_log("⚠️ VPN服务加载失败")
            log_print("✅ 启动日志输出完成")
        except Exception as e:
            log_print(f"❌ 启动日志输出失败: {e}")
        
        log_print("=" * 50)
        log_print("✅ MainScreen.__init__ 完成")
        log_print("=" * 50)
    
    def build_ui(self):
        """构建用户界面"""
        log_print("🔧 build_ui() 开始")
        
        try:
            # 标题
            log_print("   创建标题...")
            title = Label(
                text='🚀 抢单助手',
                size_hint_y=0.1,
                font_size='24sp',
                bold=True
            )
            self.add_widget(title)
            log_print("   ✅ 标题添加完成")
        except Exception as e:
            log_print(f"   ❌ 标题创建失败: {e}")
            import traceback
            log_print(traceback.format_exc())
        
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
        
        # Token 输入
        token_label = Label(text='Token (手动输入):', size_hint_y=0.05)
        self.add_widget(token_label)
        
        self.token_input = TextInput(
            text='',
            multiline=False,
            size_hint_y=0.1,
            font_size='12sp',
            hint_text='粘贴 Authorization Token...'
        )
        self.add_widget(self.token_input)
        
        # 保存Token按钮
        save_token_btn = Button(
            text='保存Token',
            size_hint_y=0.08,
            background_color=(0, 0.5, 0.8, 1),
            on_press=self.save_token
        )
        self.add_widget(save_token_btn)
        
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
        vpn_box = BoxLayout(size_hint_y=0.08, spacing=10)
        vpn_label = Label(text='VPN自动抓包:', size_hint_x=0.6)
        vpn_box.add_widget(vpn_label)
        self.vpn_switch = Switch(active=False, size_hint_x=0.4)
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
        
        # 检查Token
        token = self.token_input.text.strip()
        if not token:
            self.add_log("❌ 请先输入Token")
            return
        
        # 检查配置
        config = self.config_mgr.get_config()
        if not config.get('phone'):
            # 使用默认手机号
            config['phone'] = '18113011654'
            self.config_mgr.save_config()
        
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
            if not GrabOrderService:
                self.add_log("❌ 抢单服务模块未加载")
                self.stop_service(None)
                return
            
            if not self.config_mgr:
                self.add_log("❌ 配置管理器不可用")
                self.stop_service(None)
                return
            
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
            import traceback
            self.add_log(traceback.format_exc())
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
    
    def save_token(self, instance):
        """保存Token"""
        token = self.token_input.text.strip()
        
        if not token:
            self.add_log("❌ Token不能为空")
            return
        
        # 去掉可能的 "Bearer " 前缀
        if token.startswith('Bearer '):
            token = token[7:]
        
        self.add_log(f"💾 正在保存Token: {token[:20]}...")
        
        # 保存到配置
        if self.config_mgr:
            try:
                self.config_mgr.update_token(token, {})
            except Exception as e:
                self.add_log(f"⚠️ 配置保存失败: {e}")
        else:
            self.add_log("⚠️ 配置管理器不可用，Token仅保存在内存")
        
        # 更新抢单服务
        if self.grab_service:
            try:
                self.grab_service.update_token(token, {})
            except Exception as e:
                self.add_log(f"⚠️ 更新服务Token失败: {e}")
        
        self.add_log("✅ Token保存成功")
    
    def toggle_vpn(self, instance, value):
        """切换VPN抓包"""
        if value:
            self.add_log("🔒 正在启动VPN抓包...")
            self.start_vpn()
        else:
            self.add_log("⏹️ 正在停止VPN抓包...")
            if self.vpn_service:
                self.vpn_service.stop()
                self.vpn_service = None
    
    def start_vpn(self):
        """启动VPN抓包"""
        try:
            if not VPNTokenCapture:
                self.add_log("❌ VPN服务模块未加载")
                self.vpn_switch.active = False
                return
            
            self.vpn_service = VPNTokenCapture(
                token_callback=self.on_token_captured,
                log_callback=self.add_log
            )
            
            if ANDROID:
                success = self.vpn_service.start_vpn()
                if not success:
                    self.vpn_switch.active = False
            else:
                self.add_log("⚠️ PC模式，VPN抓包不可用")
                self.vpn_switch.active = False
                
        except Exception as e:
            self.add_log(f"❌ VPN启动失败: {e}")
            import traceback
            self.add_log(traceback.format_exc())
            self.vpn_switch.active = False
    
    @mainthread
    def on_token_captured(self, token, headers):
        """Token捕获回调"""
        self.add_log(f"🎯 捕获到新Token: {token[:20]}...")
        
        # 更新输入框
        self.token_input.text = token
        
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
        log_print("=" * 50)
        log_print("🚀 GrabOrderApp.build() 开始")
        log_print("=" * 50)
        
        try:
            log_print("🔧 设置窗口颜色...")
            Window.clearcolor = (0.1, 0.1, 0.1, 1)
            log_print("✅ 窗口颜色设置完成")
        except Exception as e:
            log_print(f"❌ 窗口颜色设置失败: {e}")
        
        try:
            log_print("🔧 注册中文字体...")
            self.register_fonts()
            log_print("✅ 字体注册完成")
        except Exception as e:
            log_print(f"❌ 字体注册失败: {e}")
            import traceback
            log_print(traceback.format_exc())
            # 继续执行，不因为字体失败而停止
        
        try:
            if ANDROID:
                log_print("🔧 请求Android权限...")
                self.request_android_permissions()
                log_print("✅ 权限请求完成")
            else:
                log_print("💻 PC环境，跳过权限请求")
        except Exception as e:
            log_print(f"❌ 权限请求失败: {e}")
            import traceback
            log_print(traceback.format_exc())
            # 继续执行，不因为权限失败而停止
        
        try:
            log_print("🔧 创建MainScreen...")
            screen = MainScreen()
            log_print("✅ MainScreen创建完成")
            log_print("=" * 50)
            log_print("🎉 GrabOrderApp.build() 完成")
            log_print("=" * 50)
            return screen
        except Exception as e:
            log_print(f"❌ MainScreen创建失败: {e}")
            import traceback
            log_print(traceback.format_exc())
            # 返回一个最简单的Label显示错误
            error_label = Label(
                text=f"启动失败: {e}\n\n请查看日志",
                color=(1, 0, 0, 1),
                text_size=(Window.width - 40, None)
            )
            return error_label
    
    def register_fonts(self):
        """注册中文字体"""
        try:
            log_print("🔤 开始注册中文字体...")
            log_print(f"   当前目录: {os.getcwd()}")
            log_print(f"   __file__: {os.path.abspath(__file__) if '__file__' in globals() else 'N/A'}")
            
            # 获取字体路径
            if ANDROID:
                # Android：尝试多个可能的路径
                base_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else '.'
                font_paths = [
                    os.path.join(base_dir, 'fonts', 'DroidSansFallback.ttf'),
                    '/data/data/com.graborder.graborder/files/fonts/DroidSansFallback.ttf',
                    'fonts/DroidSansFallback.ttf',
                    './fonts/DroidSansFallback.ttf',
                ]
            else:
                # PC：相对路径
                font_paths = [
                    'fonts/DroidSansFallback.ttf',
                    './fonts/DroidSansFallback.ttf',
                ]
            
            font_loaded = False
            for font_path in font_paths:
                try:
                    abs_path = os.path.abspath(font_path)
                    log_print(f"   尝试路径: {font_path} (绝对路径: {abs_path})")
                    if os.path.exists(font_path):
                        log_print(f"   ✅ 文件存在")
                        # 注册为默认字体
                        LabelBase.register(
                            name='Roboto',  # Kivy默认字体名称
                            fn_regular=font_path
                        )
                        log_print(f"✅ 中文字体加载成功: {font_path}")
                        font_loaded = True
                        break
                    else:
                        log_print(f"   ❌ 文件不存在")
                except Exception as e:
                    log_print(f"   ⚠️ 路径 {font_path} 检查失败: {e}")
                    continue
            
            if not font_loaded:
                log_print(f"⚠️ 未找到字体文件，使用系统默认字体（可能显示方块）")
                log_print(f"   请确保字体文件存在于以下位置之一:")
                for path in font_paths:
                    log_print(f"     - {path}")
                
        except Exception as e:
            log_print(f"❌ 字体加载过程出错: {e}")
            import traceback
            log_print(traceback.format_exc())
            log_print("⚠️ 继续使用系统默认字体")
    
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
    log_print("=" * 50)
    log_print("🚀 抢单助手启动")
    log_print("=" * 50)
    log_print(f"Python版本: {sys.version}")
    log_print(f"工作目录: {os.getcwd()}")
    log_print(f"Android模式: {ANDROID}")
    log_print("=" * 50)
    
    try:
        app = GrabOrderApp()
        log_print("✅ GrabOrderApp实例创建成功")
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
        # 尝试显示错误信息（如果Kivy可用）
        try:
            from kivy.app import App
            from kivy.uix.label import Label
            
            class ErrorApp(App):
                def build(self):
                    return Label(
                        text=f"启动失败:\n{e}\n\n请查看日志",
                        color=(1, 0, 0, 1)
                    )
            ErrorApp().run()
        except:
            pass

