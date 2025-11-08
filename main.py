#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速抢单助手 - 美化版
现代化设计，卡片式布局，渐变色
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
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.spinner import Spinner
from kivy.clock import Clock, mainthread
from kivy.properties import StringProperty, BooleanProperty, NumericProperty
from kivy.core.window import Window
from kivy.graphics import Color, RoundedRectangle, Rectangle
from kivy.uix.widget import Widget

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


# ==================== 字体注册（官方方案，修复中文乱码）====================
from kivy.core.text import LabelBase
from kivy.resources import resource_add_path

# 添加字体路径
app_dir = os.path.dirname(os.path.abspath(__file__))
fonts_dir = os.path.join(app_dir, 'fonts')
if os.path.exists(fonts_dir):
    resource_add_path(fonts_dir)
    log_print(f"✅ 字体路径已添加: {fonts_dir}")
else:
    log_print(f"⚠️ 字体目录不存在: {fonts_dir}")

# 注册中文字体（官方 API: LabelBase.register）
try:
    LabelBase.register(
        name='ChineseFont',
        fn_regular='DroidSansFallback.ttf'
    )
    log_print("✅ 中文字体注册成功: DroidSansFallback.ttf")
except Exception as e:
    log_print(f"⚠️ 字体注册失败: {e}")
    # 如果注册失败，使用 Kivy 默认字体（可能显示方块）
    import traceback
    log_print(traceback.format_exc())
# ========================================================================


class RoundedButton(Button):
    """圆角按钮"""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.background_color = (0, 0, 0, 0)  # 透明背景
        self.background_normal = ''
        
        with self.canvas.before:
            self.bg_color = Color(0.2, 0.7, 0.3, 1)
            self.bg_rect = RoundedRectangle(size=self.size, pos=self.pos, radius=[15])
        
        self.bind(pos=self.update_rect, size=self.update_rect)
    
    def update_rect(self, *args):
        self.bg_rect.pos = self.pos
        self.bg_rect.size = self.size
    
    def set_color(self, r, g, b, a=1):
        """设置按钮颜色"""
        self.bg_color.rgba = (r, g, b, a)


class StatusCard(BoxLayout):
    """状态卡片"""
    def __init__(self, title, value, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = [15, 10]
        self.spacing = 5
        
        # 卡片背景
        with self.canvas.before:
            Color(0.15, 0.15, 0.18, 1)
            self.bg_rect = RoundedRectangle(size=self.size, pos=self.pos, radius=[12])
        
        self.bind(pos=self.update_bg, size=self.update_bg)
        
        # 标题
        self.title_label = Label(
            text=title,
            font_size='12sp',
            size_hint_y=0.4,
            color=(0.7, 0.7, 0.7, 1),
            font_name='ChineseFont'
        )
        self.add_widget(self.title_label)
        
        # 值
        self.value_label = Label(
            text=value,
            font_size='15sp',
            bold=True,
            size_hint_y=0.6,
            color=(1, 1, 1, 1),
            font_name='ChineseFont'
        )
        self.add_widget(self.value_label)
    
    def update_bg(self, *args):
        self.bg_rect.pos = self.pos
        self.bg_rect.size = self.size
    
    def set_value(self, value, color=None):
        """设置值和颜色"""
        self.value_label.text = value
        if color:
            self.value_label.color = color


class MainScreen(BoxLayout):
    """主界面 - 美化版"""
    
    frida_status = StringProperty("未启动")
    hook_status = StringProperty("未连接")
    token_status = StringProperty("未获取")
    grab_status = StringProperty("未启动")
    log_text = StringProperty("")
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        self.orientation = 'vertical'
        self.padding = 15
        self.spacing = 12
        
        # 背景渐变
        with self.canvas.before:
            Color(0.08, 0.08, 0.12, 1)
            self.bg_rect = Rectangle(size=self.size, pos=self.pos)
        
        self.bind(pos=self.update_bg, size=self.update_bg)
        
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
        
        self.add_log("🚀 快速抢单助手 - 美化版")
        self.add_log(f"📱 环境: {'Android' if ANDROID else 'PC'}")
        
        if not FRIDA_MANAGER_AVAILABLE:
            self.add_log("⚠️ Frida 管理器不可用")
        if not AUTO_HOOK_AVAILABLE:
            self.add_log("⚠️ Hook 服务不可用")
        if not GRAB_SERVICE_AVAILABLE:
            self.add_log("⚠️ 抢单服务不可用")
    
    def update_bg(self, *args):
        self.bg_rect.pos = self.pos
        self.bg_rect.size = self.size
    
    def build_ui(self):
        """构建界面"""
        # 标题栏
        header = BoxLayout(size_hint_y=0.08, spacing=10)
        header.add_widget(Widget(size_hint_x=0.1))
        title = Label(
            text='⚡ 快速抢单助手',
            font_size='24sp',
            bold=True,
            color=(1, 1, 1, 1),
            size_hint_x=0.8,
            font_name='ChineseFont'
        )
        header.add_widget(title)
        header.add_widget(Widget(size_hint_x=0.1))
        self.add_widget(header)
        
        # 状态卡片区域
        status_container = BoxLayout(size_hint_y=0.18, spacing=8)
        
        # Frida 状态卡片
        self.frida_card = StatusCard('Frida', self.frida_status)
        status_container.add_widget(self.frida_card)
        
        # Hook 状态卡片
        self.hook_card = StatusCard('Hook', self.hook_status)
        status_container.add_widget(self.hook_card)
        
        # Token 状态卡片
        self.token_card = StatusCard('Token', self.token_status)
        status_container.add_widget(self.token_card)
        
        # 抢单状态卡片
        self.grab_card = StatusCard('抢单', self.grab_status)
        status_container.add_widget(self.grab_card)
        
        self.add_widget(status_container)
        
        # 配置面板（卡片式）
        config_panel = BoxLayout(size_hint_y=0.20, orientation='vertical', spacing=8, padding=[5, 10])
        
        # 配置面板背景
        with config_panel.canvas.before:
            Color(0.12, 0.12, 0.15, 1)
            config_bg = RoundedRectangle(size=config_panel.size, pos=config_panel.pos, radius=[15])
        
        config_panel.bind(
            pos=lambda inst, val: setattr(config_bg, 'pos', val),
            size=lambda inst, val: setattr(config_bg, 'size', val)
        )
        
        # 目标应用
        app_box = BoxLayout(size_hint_y=0.33, spacing=10, padding=[15, 5])
        app_label = Label(
            text='📱 目标应用',
            size_hint_x=0.35,
            font_size='13sp',
            color=(0.8, 0.8, 0.8, 1),
            font_name='ChineseFont'
        )
        app_box.add_widget(app_label)
        
        self.package_input = TextInput(
            text=self.target_package,
            multiline=False,
            size_hint_x=0.65,
            font_size='12sp',
            background_color=(0.2, 0.2, 0.23, 1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(0.3, 0.7, 1, 1),
            padding=[10, 8],
            font_name='ChineseFont'
        )
        app_box.add_widget(self.package_input)
        config_panel.add_widget(app_box)
        
        # 检查间隔
        interval_box = BoxLayout(size_hint_y=0.33, spacing=10, padding=[15, 5])
        interval_label = Label(
            text='⏱️ 检查间隔',
            size_hint_x=0.35,
            font_size='13sp',
            color=(0.8, 0.8, 0.8, 1),
            font_name='ChineseFont'
        )
        interval_box.add_widget(interval_label)
        
        self.interval_spinner = Spinner(
            text='1秒',
            values=('0.5秒', '1秒', '2秒', '3秒'),
            size_hint_x=0.65,
            font_size='12sp',
            background_color=(0.2, 0.2, 0.23, 1),
            color=(1, 1, 1, 1),
            font_name='ChineseFont'
        )
        interval_box.add_widget(self.interval_spinner)
        config_panel.add_widget(interval_box)
        
        # 商品类别
        category_box = BoxLayout(size_hint_y=0.33, spacing=10, padding=[15, 5])
        category_label = Label(
            text='🏷️ 商品类别',
            size_hint_x=0.35,
            font_size='13sp',
            color=(0.8, 0.8, 0.8, 1),
            font_name='ChineseFont'
        )
        category_box.add_widget(category_label)
        
        self.category_input = TextInput(
            text='2469',
            multiline=False,
            size_hint_x=0.65,
            font_size='12sp',
            background_color=(0.2, 0.2, 0.23, 1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(0.3, 0.7, 1, 1),
            padding=[10, 8],
            font_name='ChineseFont'
        )
        category_box.add_widget(self.category_input)
        config_panel.add_widget(category_box)
        
        self.add_widget(config_panel)
        
        # 控制按钮
        btn_container = BoxLayout(size_hint_y=0.12, spacing=15, padding=[10, 5])
        
        # 启动按钮
        self.start_btn = RoundedButton(text='🚀 启动抢单', font_size='16sp', bold=True, font_name='ChineseFont')
        self.start_btn.set_color(0.2, 0.7, 0.3)  # 绿色
        self.start_btn.bind(on_press=self.start_all_services)
        btn_container.add_widget(self.start_btn)
        
        # 停止按钮
        self.stop_btn = RoundedButton(text='⏹️ 停止', font_size='16sp', bold=True, font_name='ChineseFont')
        self.stop_btn.set_color(0.7, 0.2, 0.2)  # 红色
        self.stop_btn.disabled = True
        self.stop_btn.bind(on_press=self.stop_all_services)
        btn_container.add_widget(self.stop_btn)
        
        self.add_widget(btn_container)
        
        # 日志区域（卡片式）
        log_header = Label(
            text='📋 运行日志',
            size_hint_y=0.04,
            font_size='14sp',
            bold=True,
            color=(0.9, 0.9, 0.9, 1),
            halign='left',
            font_name='ChineseFont'
        )
        log_header.bind(size=log_header.setter('text_size'))
        self.add_widget(log_header)
        
        # 日志容器
        log_container = BoxLayout(size_hint_y=0.38, padding=[5, 5])
        
        with log_container.canvas.before:
            Color(0.1, 0.1, 0.13, 1)
            log_bg = RoundedRectangle(size=log_container.size, pos=log_container.pos, radius=[12])
        
        log_container.bind(
            pos=lambda inst, val: setattr(log_bg, 'pos', val),
            size=lambda inst, val: setattr(log_bg, 'size', val)
        )
        
        scroll = ScrollView()
        self.log_display = Label(
            text='',
            size_hint_y=None,
            halign='left',
            valign='top',
            font_size='11sp',
            color=(0.85, 0.85, 0.85, 1),
            padding=[10, 10],
            font_name='ChineseFont'
        )
        self.log_display.bind(texture_size=self.log_display.setter('size'))
        self.log_display.bind(size=self.log_display.setter('text_size'))
        scroll.add_widget(self.log_display)
        log_container.add_widget(scroll)
        
        self.add_widget(log_container)
    
    def start_all_services(self, instance):
        """启动所有服务"""
        self.add_log("")
        self.add_log("=" * 50)
        self.add_log("🚀 开始启动服务...")
        self.add_log("=" * 50)
        
        # 禁用启动按钮，启用停止按钮
        self.start_btn.disabled = True
        self.stop_btn.disabled = False
        
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
            self.frida_card.set_value("✅ 运行中", (0.3, 0.9, 0.3, 1))
            
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
            self.hook_card.set_value("🔄 连接中", (1, 0.8, 0.3, 1))
            
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
        pass
    
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
        
        self.token_status = f"✅ {token[:10]}..."
        self.token_card.set_value(f"✅ {token[:10]}...", (0.3, 0.9, 0.3, 1))
        
        self.hook_status = "✅ 已连接"
        self.hook_card.set_value("✅ 已连接", (0.3, 0.9, 0.3, 1))
        
        # 更新抢单服务
        if self.grab_service:
            self.grab_service.update_token(token_data)
            
            # 启动抢单
            if not self.grab_service.running:
                self.add_log("")
                self.add_log("🚀 自动启动抢单服务...")
                self.grab_service.start()
                self.grab_status = "✅ 运行中"
                self.grab_card.set_value("✅ 运行中", (0.3, 0.9, 0.3, 1))
    
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
            self.grab_card.set_value("已停止", (0.7, 0.7, 0.7, 1))
        
        if self.hook_service:
            self.hook_service.stop()
            self.hook_service = None
            self.hook_status = "未连接"
            self.hook_card.set_value("未连接", (0.7, 0.7, 0.7, 1))
        
        if self.frida_manager:
            self.frida_manager = None
        
        self.token_status = "未获取"
        self.token_card.set_value("未获取", (0.7, 0.7, 0.7, 1))
        
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
        self.log_display.text = self.log_text


class FastGrabOrderApp(App):
    """主应用"""
    
    def build(self):
        # 深色主题背景
        Window.clearcolor = (0.08, 0.08, 0.12, 1)
        
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
    log_print("🚀 快速抢单助手 - 美化版")
    log_print("=" * 50)
    
    try:
        app = FastGrabOrderApp()
        app.run()
    except Exception as e:
        log_print(f"❌ 启动失败: {e}")
        import traceback
        log_print(traceback.format_exc())

