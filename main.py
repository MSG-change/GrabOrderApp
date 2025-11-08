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
    
    # 字体名称（如果字体加载成功）
    _font_name = None
    
    @classmethod
    def set_font_name(cls, font_name):
        """设置字体名称"""
        cls._font_name = font_name
    
    def _get_font_kwargs(self):
        """获取字体参数"""
        if self._font_name:
            return {'font_name': self._font_name}
        return {}
    
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
        
        # 获取字体参数
        font_kwargs = self._get_font_kwargs()
        log_print(f"   字体参数: {font_kwargs}")
        
        try:
            # 标题
            log_print("   创建标题...")
            title = Label(
                text='🚀 抢单助手',
                size_hint_y=0.1,
                font_size='24sp',
                bold=True,
                **font_kwargs
            )
            self.add_widget(title)
            log_print("   ✅ 标题添加完成")
        except Exception as e:
            log_print(f"   ❌ 标题创建失败: {e}")
            import traceback
            log_print(traceback.format_exc())
        
        # 状态显示
        try:
            log_print("   创建状态显示...")
            status_box = BoxLayout(size_hint_y=0.1, spacing=10)
            log_print("   ✅ status_box创建完成")
            status_box.add_widget(Label(text='状态:', size_hint_x=0.3, **font_kwargs))
            log_print("   ✅ 状态Label添加完成")
            self.status_label = Label(
                text=self.status_text,
                size_hint_x=0.7,
                color=(0, 1, 0, 1),
                **font_kwargs
            )
            log_print("   ✅ status_label创建完成")
            status_box.add_widget(self.status_label)
            log_print("   ✅ status_label添加到status_box")
            self.add_widget(status_box)
            log_print("   ✅ status_box添加到主界面")
        except Exception as e:
            log_print(f"   ❌ 状态显示创建失败: {e}")
            import traceback
            log_print(traceback.format_exc())
        
        # Token 输入
        try:
            log_print("   创建Token输入...")
            token_label = Label(text='Token (手动输入):', size_hint_y=0.05, **font_kwargs)
            log_print("   ✅ token_label创建完成")
            self.add_widget(token_label)
            log_print("   ✅ token_label添加完成")
            
            log_print("   创建TextInput...")
            self.token_input = TextInput(
                text='',
                multiline=False,
                size_hint_y=0.1,
                font_size='12sp',
                hint_text='Paste Authorization Token...',  # 英文提示，避免字体问题
                **font_kwargs
            )
            log_print("   ✅ token_input创建完成")
            self.add_widget(self.token_input)
            log_print("   ✅ token_input添加完成")
        except Exception as e:
            log_print(f"   ❌ Token输入创建失败: {e}")
            import traceback
            log_print(traceback.format_exc())
        
        # 保存Token按钮
        try:
            log_print("   创建保存Token按钮...")
            save_token_btn = Button(
                text='保存Token',
                size_hint_y=0.08,
                background_color=(0, 0.5, 0.8, 1),
                on_press=self.save_token,
                **font_kwargs
            )
            log_print("   ✅ save_token_btn创建完成")
            self.add_widget(save_token_btn)
            log_print("   ✅ save_token_btn添加完成")
        except Exception as e:
            log_print(f"   ❌ 保存Token按钮创建失败: {e}")
            import traceback
            log_print(traceback.format_exc())
        
        # 控制按钮
        try:
            log_print("   创建控制按钮...")
            btn_box = BoxLayout(size_hint_y=0.15, spacing=10)
            log_print("   ✅ btn_box创建完成")
            
            self.start_btn = Button(
                text='启动抢单',
                background_color=(0, 0.7, 0, 1),
                on_press=self.start_service,
                **font_kwargs
            )
            log_print("   ✅ start_btn创建完成")
            btn_box.add_widget(self.start_btn)
            log_print("   ✅ start_btn添加到btn_box")
            
            self.stop_btn = Button(
                text='停止',
                background_color=(0.7, 0, 0, 1),
                disabled=True,
                on_press=self.stop_service,
                **font_kwargs
            )
            log_print("   ✅ stop_btn创建完成")
            btn_box.add_widget(self.stop_btn)
            log_print("   ✅ stop_btn添加到btn_box")
            
            self.add_widget(btn_box)
            log_print("   ✅ btn_box添加到主界面")
        except Exception as e:
            log_print(f"   ❌ 控制按钮创建失败: {e}")
            import traceback
            log_print(traceback.format_exc())
        
        # VPN 抓包开关
        try:
            log_print("   创建VPN开关...")
            vpn_box = BoxLayout(size_hint_y=0.08, spacing=10)
            log_print("   ✅ vpn_box创建完成")
            vpn_label = Label(text='VPN自动抓包:', size_hint_x=0.6, **font_kwargs)
            log_print("   ✅ vpn_label创建完成")
            vpn_box.add_widget(vpn_label)
            log_print("   ✅ vpn_label添加到vpn_box")
            self.vpn_switch = Switch(active=False, size_hint_x=0.4)
            log_print("   ✅ vpn_switch创建完成")
            self.vpn_switch.bind(active=self.toggle_vpn)
            log_print("   ✅ vpn_switch绑定完成")
            vpn_box.add_widget(self.vpn_switch)
            log_print("   ✅ vpn_switch添加到vpn_box")
            self.add_widget(vpn_box)
            log_print("   ✅ vpn_box添加到主界面")
        except Exception as e:
            log_print(f"   ❌ VPN开关创建失败: {e}")
            import traceback
            log_print(traceback.format_exc())
        
        # 日志显示
        try:
            log_print("   创建日志显示...")
            log_label = Label(
                text='运行日志:',
                size_hint_y=0.05,
                halign='left',
                **font_kwargs
            )
            log_print("   ✅ log_label创建完成")
            self.add_widget(log_label)
            log_print("   ✅ log_label添加完成")
            
            log_print("   创建ScrollView...")
            scroll = ScrollView(size_hint_y=0.5)
            log_print("   ✅ scroll创建完成")
            self.log_display = Label(
                text='',
                size_hint_y=None,
                halign='left',
                valign='top',
                font_size='12sp',
                color=(0.8, 0.8, 0.8, 1),
                **font_kwargs
            )
            log_print("   ✅ log_display创建完成")
            self.log_display.bind(texture_size=self.log_display.setter('size'))
            log_print("   ✅ log_display绑定完成")
            scroll.add_widget(self.log_display)
            log_print("   ✅ log_display添加到scroll")
            self.add_widget(scroll)
            log_print("   ✅ scroll添加到主界面")
        except Exception as e:
            log_print(f"   ❌ 日志显示创建失败: {e}")
            import traceback
            log_print(traceback.format_exc())
        
        log_print("   ✅ build_ui() 所有组件创建完成")
    
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
        # 立即输出，确保即使后续出错也能看到
        try:
            print("=" * 50)
            print("🚀 GrabOrderApp.build() 开始")
            print("=" * 50)
        except:
            pass
        
        log_print("=" * 50)
        log_print("🚀 GrabOrderApp.build() 开始 (log_print)")
        log_print("=" * 50)
        
        try:
            log_print("🔧 设置窗口颜色...")
            Window.clearcolor = (0.1, 0.1, 0.1, 1)
            log_print("✅ 窗口颜色设置完成")
        except Exception as e:
            log_print(f"❌ 窗口颜色设置失败: {e}")
            import traceback
            log_print(traceback.format_exc())
        
        try:
            log_print("🔧 注册中文字体...")
            font_name = self.register_fonts()
            if font_name:
                MainScreen.set_font_name(font_name)
                log_print(f"✅ 字体注册完成，字体名称: {font_name}")
            else:
                log_print("⚠️ 字体注册失败，将使用系统默认字体")
        except Exception as e:
            log_print(f"❌ 字体注册失败: {e}")
            import traceback
            log_print(traceback.format_exc())
            # 继续执行，不因为字体失败而停止
        
        # 权限请求移到创建MainScreen之后，使用延迟请求
        # 这样不会阻塞UI的创建
        if ANDROID:
            log_print("🔧 Android环境，将在UI创建后请求权限")
        else:
            log_print("💻 PC环境，跳过权限请求")
        
        try:
            log_print("🔧 创建MainScreen...")
            screen = MainScreen()
            log_print("✅ MainScreen创建完成")
            
            # 在UI创建后延迟请求权限（避免阻塞UI显示）
            if ANDROID:
                def request_permissions_delayed(dt):
                    try:
                        log_print("🔧 延迟请求Android权限...")
                        self.request_android_permissions()
                        log_print("✅ 权限请求完成")
                    except Exception as e:
                        log_print(f"❌ 权限请求失败: {e}")
                
                Clock.schedule_once(request_permissions_delayed, 0.5)
            
            log_print("=" * 50)
            log_print("🎉 GrabOrderApp.build() 完成")
            log_print("=" * 50)
            return screen
        except Exception as e:
            log_print("=" * 50)
            log_print("❌ MainScreen创建失败!")
            log_print("=" * 50)
            log_print(f"错误: {e}")
            import traceback
            error_trace = traceback.format_exc()
            log_print(error_trace)
            log_print("=" * 50)
            # 返回一个最简单的Label显示错误
            try:
                error_label = Label(
                    text=f"启动失败\n\n错误: {str(e)}\n\n请查看logcat日志获取详细信息",
                    color=(1, 0, 0, 1),
                    halign='center',
                    valign='middle',
                    text_size=(Window.width - 40, None) if hasattr(Window, 'width') else (None, None),
                    font_size='18sp'
                )
                log_print("✅ 错误Label创建成功")
                return error_label
            except Exception as e2:
                log_print(f"❌ 连错误Label都创建失败: {e2}")
                # 最后的备用方案：返回None，让Kivy使用默认界面
                return None
    
    def register_fonts(self):
        """注册中文字体"""
        try:
            log_print("🔤 开始注册中文字体...")
            log_print(f"   当前目录: {os.getcwd()}")
            log_print(f"   __file__: {os.path.abspath(__file__) if '__file__' in globals() else 'N/A'}")
            
            # 获取字体路径
            if ANDROID:
                # Android：尝试多个可能的路径
                log_print("   📱 Android环境：开始加载字体")
                base_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else '.'
                font_paths = [
                    os.path.join(os.getcwd(), 'fonts', 'DroidSansFallback.ttf'),
                    os.path.join(base_dir, 'fonts', 'DroidSansFallback.ttf'),
                    '/data/data/com.graborder.graborder/files/app/fonts/DroidSansFallback.ttf',
                    '/data/data/com.graborder.graborder/files/fonts/DroidSansFallback.ttf',
                    'fonts/DroidSansFallback.ttf',
                    './fonts/DroidSansFallback.ttf',
                    # Kivy Android assets路径
                    os.path.join(os.path.dirname(__file__) if '__file__' in globals() else '.', 'fonts', 'DroidSansFallback.ttf'),
                ]
                
                font_loaded = False
                for font_path in font_paths:
                    try:
                        abs_path = os.path.abspath(font_path) if not os.path.isabs(font_path) else font_path
                        log_print(f"   📱 尝试路径: {font_path}")
                        log_print(f"      绝对路径: {abs_path}")
                        if os.path.exists(font_path) or os.path.exists(abs_path):
                            actual_path = font_path if os.path.exists(font_path) else abs_path
                            log_print(f"   ✅ 文件存在: {actual_path}")
                            # 注册为自定义字体名称
                            LabelBase.register(
                                name='DroidSansFallback',
                                fn_regular=actual_path
                            )
                            # 也注册为默认字体（覆盖Roboto）
                            LabelBase.register(
                                name='Roboto',
                                fn_regular=actual_path
                            )
                            log_print(f"✅ Android字体加载成功: {actual_path}")
                            font_loaded = True
                            return 'DroidSansFallback'
                        else:
                            log_print(f"   ❌ 文件不存在")
                    except Exception as e:
                        log_print(f"   ⚠️ 路径 {font_path} 检查失败: {e}")
                        import traceback
                        log_print(traceback.format_exc())
                        continue
                
                if not font_loaded:
                    log_print("⚠️ Android：未找到字体文件，将使用系统默认字体（可能显示方块）")
                    log_print("   请确保字体文件存在于以下位置之一:")
                    for path in font_paths:
                        log_print(f"     - {path}")
                    return None
            else:
                # PC：尝试使用系统自带的中文字体
                import platform
                system = platform.system()
                
                if system == 'Darwin':  # macOS
                    # Mac系统自带中文字体路径
                    mac_font_paths = [
                        '/System/Library/Fonts/PingFang.ttc',
                        '/System/Library/Fonts/STHeiti Light.ttc',
                        '/System/Library/Fonts/STHeiti Medium.ttc',
                        '/Library/Fonts/Arial Unicode.ttf',
                    ]
                    
                    for font_path in mac_font_paths:
                        if os.path.exists(font_path):
                            try:
                                log_print(f"   💻 尝试使用Mac系统字体: {font_path}")
                                LabelBase.register(
                                    name='DroidSansFallback',
                                    fn_regular=font_path
                                )
                                LabelBase.register(
                                    name='Roboto',
                                    fn_regular=font_path
                                )
                                log_print(f"✅ Mac系统字体加载成功: {font_path}")
                                return 'DroidSansFallback'
                            except Exception as e:
                                log_print(f"   ⚠️ 系统字体加载失败: {e}")
                                continue
                    
                    # 如果系统字体都失败，尝试项目字体
                    log_print("   💻 系统字体加载失败，尝试项目字体...")
                    font_paths = [
                        'fonts/DroidSansFallback.ttf',
                        './fonts/DroidSansFallback.ttf',
                        os.path.join(os.path.dirname(__file__), 'fonts', 'DroidSansFallback.ttf'),
                    ]
                    for font_path in font_paths:
                        if os.path.exists(font_path):
                            try:
                                abs_path = os.path.abspath(font_path)
                                log_print(f"   尝试路径: {font_path} (绝对路径: {abs_path})")
                                LabelBase.register(
                                    name='DroidSansFallback',
                                    fn_regular=abs_path
                                )
                                LabelBase.register(
                                    name='Roboto',
                                    fn_regular=abs_path
                                )
                                log_print(f"✅ 项目字体加载成功: {font_path}")
                                return 'DroidSansFallback'
                            except Exception as e:
                                log_print(f"   ⚠️ 项目字体加载失败: {e}")
                                continue
                    
                    log_print("   ⚠️ 所有字体加载失败，使用系统默认字体")
                    return None
                else:
                    # Linux/Windows：尝试加载项目字体
                    font_paths = [
                        'fonts/DroidSansFallback.ttf',
                        './fonts/DroidSansFallback.ttf',
                        os.path.join(os.path.dirname(__file__), 'fonts', 'DroidSansFallback.ttf'),
                    ]
                    for font_path in font_paths:
                        if os.path.exists(font_path):
                            try:
                                abs_path = os.path.abspath(font_path)
                                LabelBase.register(
                                    name='DroidSansFallback',
                                    fn_regular=abs_path
                                )
                                log_print(f"✅ 字体加载成功: {font_path}")
                                return 'DroidSansFallback'
                            except Exception as e:
                                log_print(f"   ⚠️ 字体加载失败: {e}")
                                continue
                    log_print("   ⚠️ 字体加载失败，使用系统默认字体")
                    return None
                
        except Exception as e:
            log_print(f"❌ 字体加载过程出错: {e}")
            import traceback
            log_print(traceback.format_exc())
            log_print("⚠️ 继续使用系统默认字体")
            return None
    
    def request_android_permissions(self):
        """请求Android权限"""
        try:
            # 只请求基本的必要权限
            permissions = [
                Permission.INTERNET,
                Permission.ACCESS_NETWORK_STATE,
            ]
            
            # 尝试请求可选权限（如果存在）
            try:
                permissions.append(Permission.WRITE_EXTERNAL_STORAGE)
                permissions.append(Permission.READ_EXTERNAL_STORAGE)
            except:
                log_print("⚠️ 存储权限不可用（可能Android版本较新）")
            
            log_print(f"🔧 请求权限: {permissions}")
            request_permissions(permissions)
            log_print("✅ 权限请求已发送")
        except Exception as e:
            log_print(f"❌ 权限请求出错: {e}")
            import traceback
            log_print(traceback.format_exc())
    
    def on_pause(self):
        """应用暂停（保持后台运行）"""
        return True
    
    def on_resume(self):
        """应用恢复"""
        pass


if __name__ == '__main__':
    # 立即输出启动信息（使用print确保在log_print初始化之前也能看到）
    try:
        print("=" * 50)
        print("🚀 抢单助手启动")
        print("=" * 50)
        print(f"Python版本: {sys.version}")
        print(f"工作目录: {os.getcwd()}")
        print(f"Android模式: {ANDROID}")
        print("=" * 50)
    except:
        pass
    
    log_print("=" * 50)
    log_print("🚀 抢单助手启动 (log_print)")
    log_print("=" * 50)
    log_print(f"Python版本: {sys.version}")
    log_print(f"工作目录: {os.getcwd()}")
    log_print(f"Android模式: {ANDROID}")
    log_print("=" * 50)
    
    # 预加载字体（在应用启动前）
    if not ANDROID:
        # PC环境：尝试加载Mac系统字体或项目字体
        import platform
        system = platform.system()
        
        if system == 'Darwin':  # macOS
            font_loaded = False
            # 首先尝试Mac系统字体
            mac_font_paths = [
                '/System/Library/Fonts/PingFang.ttc',
                '/System/Library/Fonts/STHeiti Light.ttc',
                '/System/Library/Fonts/STHeiti Medium.ttc',
                '/Library/Fonts/Arial Unicode.ttf',
            ]
            
            for font_path in mac_font_paths:
                if os.path.exists(font_path):
                    try:
                        LabelBase.register(
                            name='DroidSansFallback',
                            fn_regular=font_path
                        )
                        LabelBase.register(
                            name='Roboto',
                            fn_regular=font_path
                        )
                        MainScreen.set_font_name('DroidSansFallback')
                        log_print(f"✅ Mac系统字体预加载成功: {font_path}")
                        font_loaded = True
                        break
                    except Exception as e:
                        log_print(f"⚠️ Mac系统字体预加载失败: {e}")
                        continue
            
            # 如果系统字体失败，尝试项目字体
            if not font_loaded:
                font_paths = [
                    'fonts/DroidSansFallback.ttf',
                    './fonts/DroidSansFallback.ttf',
                    os.path.join(os.path.dirname(__file__), 'fonts', 'DroidSansFallback.ttf'),
                ]
                for font_path in font_paths:
                    if os.path.exists(font_path):
                        try:
                            abs_path = os.path.abspath(font_path)
                            LabelBase.register(
                                name='DroidSansFallback',
                                fn_regular=abs_path
                            )
                            LabelBase.register(
                                name='Roboto',
                                fn_regular=abs_path
                            )
                            MainScreen.set_font_name('DroidSansFallback')
                            log_print(f"✅ 项目字体预加载成功: {font_path}")
                            font_loaded = True
                            break
                        except Exception as e:
                            log_print(f"⚠️ 项目字体预加载失败: {e}")
                            continue
            
            if not font_loaded:
                log_print("⚠️ PC环境：所有字体预加载失败，将使用系统默认字体（中文可能显示为方块）")
        else:
            # Linux/Windows：尝试加载项目字体
            font_paths = [
                'fonts/DroidSansFallback.ttf',
                './fonts/DroidSansFallback.ttf',
                os.path.join(os.path.dirname(__file__), 'fonts', 'DroidSansFallback.ttf'),
            ]
            font_loaded = False
            for font_path in font_paths:
                if os.path.exists(font_path):
                    try:
                        LabelBase.register(
                            name='DroidSansFallback',
                            fn_regular=font_path
                        )
                        LabelBase.register(
                            name='Roboto',
                            fn_regular=font_path
                        )
                        MainScreen.set_font_name('DroidSansFallback')
                        log_print(f"✅ 字体预加载成功: {font_path}")
                        font_loaded = True
                        break
                    except Exception as e:
                        log_print(f"⚠️ 字体预加载失败: {e}")
                        continue
            if not font_loaded:
                log_print("⚠️ PC环境：字体预加载失败，将使用系统默认字体")
    else:
        try:
            font_paths = [
                'fonts/DroidSansFallback.ttf',
                './fonts/DroidSansFallback.ttf',
                os.path.join(os.path.dirname(__file__), 'fonts', 'DroidSansFallback.ttf'),
            ]
            font_loaded = False
            for font_path in font_paths:
                if os.path.exists(font_path):
                    try:
                        LabelBase.register(
                            name='DroidSansFallback',
                            fn_regular=font_path
                        )
                        LabelBase.register(
                            name='Roboto',
                            fn_regular=font_path
                        )
                        MainScreen.set_font_name('DroidSansFallback')
                        log_print(f"✅ 字体预加载成功: {font_path}")
                        font_loaded = True
                        break
                    except Exception as e:
                        log_print(f"⚠️ 字体注册失败: {e}")
                        continue
            if not font_loaded:
                log_print("⚠️ 未找到字体文件，将使用系统默认字体")
        except Exception as e:
            log_print(f"⚠️ 字体预加载失败: {e}")
    
    try:
        print("🔧 准备创建GrabOrderApp实例...")
        log_print("🔧 准备创建GrabOrderApp实例...")
        app = GrabOrderApp()
        print("✅ GrabOrderApp实例创建成功")
        log_print("✅ GrabOrderApp实例创建成功")
        print("🔧 开始运行应用...")
        log_print("🔧 开始运行应用...")
        app.run()
    except Exception as e:
        print("=" * 50)
        print("❌ 应用启动失败！")
        print(f"错误: {e}")
        import traceback
        print(traceback.format_exc())
        print("=" * 50)
        
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

