#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pure APK Internal Frida Integration Service
Optimized for MuMu emulator and ARM64 devices
All Frida functions run inside APK
"""

import os
import sys
import json
import time
import threading
import subprocess
from pathlib import Path

# APK internal Frida import
try:
    import frida
    FRIDA_AVAILABLE = True
    print("✅ Frida library loaded")
except ImportError as e:
    FRIDA_AVAILABLE = False
    print(f"❌ Frida library load failed: {e}")
    print("   This indicates Frida was not properly included during APK build")

try:
    from jnius import autoclass, cast
    ANDROID_AVAILABLE = True
except ImportError:
    ANDROID_AVAILABLE = False
    print("⚠️ Android JNI not available (only available in APK environment)")


class FridaAPKService:
    """
    Pure APK internal Frida service
    All Frida functions run inside APK, no external Frida Server needed
    """

    def __init__(self, target_package="com.dys.shzs", log_callback=None):
        """
        Initialize

        Args:
            target_package: Target APP package name
            log_callback: Log callback function
        """
        self.target_package = target_package
        self.log_callback = log_callback

        self.running = False
        self.thread = None

        # Frida 相关
        self.device = None
        self.session = None
        self.script = None

        # Token 数据
        self.token_data = {
            'token': '',
            'club_id': '',
            'role_id': '',
            'tenant_id': '',
            'timestamp': 0
        }

        # Token 更新回调
        self.token_callback = None

        # APK 内部 Frida Server 管理
        self.frida_server_path = None
        self.server_process = None

        # 环境检测
        self.is_apk = self._check_apk_environment()

    def _check_apk_environment(self):
        """Check if running in APK environment"""
        try:
            # Check Android environment markers
            if hasattr(sys, '_MEIPASS'):
                return False  # PyInstaller environment

            # Check Kivy/Android environment
            if ANDROID_AVAILABLE:
                try:
                    from kivy.utils import platform
                    if platform == 'android':
                        self.log("📱 Android/APK environment detected")
                        return True
                except:
                    pass

            # Check key files
            apk_markers = [
                '/data/data',
                'android',
                'PythonActivity'
            ]

            for marker in apk_markers:
                if marker in str(sys.path) or marker in os.getcwd():
                    self.log("📱 APK environment detected")
                    return True

        except Exception as e:
            self.log(f"⚠️ Environment detection failed: {e}")

        self.log("💻 PC environment detected")
        return False

    def set_token_callback(self, callback):
        """Set token update callback"""
        self.token_callback = callback

    def start(self):
        """Start Frida service"""
        if self.running:
            self.log("⚠️ Frida service already running")
            return False

        self.running = True
        self.log("🚀 Starting pure APK Frida service")

        # Step 1: Environment check
        if not self._prepare_environment():
            self.log("❌ Environment preparation failed")
            return False

        # Step 2: Start Frida Server (if needed)
        if not self._start_frida_server():
            self.log("❌ Frida Server startup failed")
            return False

        # Step 3: Connect Frida and inject
        if not self._connect_and_inject():
            self.log("❌ Frida connection injection failed")
            return False

        self.log("✅ Pure APK Frida service started successfully")
        return True

    def _prepare_environment(self):
        """Prepare environment"""
        try:
            self.log("🔧 Preparing Frida environment...")

            if not FRIDA_AVAILABLE:
                self.log("⚠️ Frida library not available in current environment")
                self.log("   This is normal for APK builds - Frida will be included at runtime")
                # Don't return False - allow service to start with limited functionality
                return True

            # In APK environment, Frida should already be available
            if self.is_apk:
                self.log("✅ APK environment Frida check passed")
                return True
            else:
                self.log("⚠️ Non-APK environment, may need external Frida Server")
                return True  # Continue trying

        except Exception as e:
            self.log(f"⚠️ Environment preparation warning: {e}")
            self.log("   Continuing with limited Frida functionality")
            return True  # Don't fail completely

    def _start_frida_server(self):
        """Start Frida Server (APK internal)"""
        try:
            # In APK environment, Frida Server usually doesn't need manual startup
            # Because we use Frida's Python API directly

            if self.is_apk:
                self.log("📱 APK environment skips Frida Server startup")
                return True

            # PC 环境：检查是否有 Frida Server 运行
            self.log("💻 检查 Frida Server 状态...")
            try:
                # 尝试连接本地 Frida Server
                self.device = frida.get_usb_device(timeout=3)
                self.log("✅ Frida Server 已运行")
                return True
            except:
                self.log("⚠️ Frida Server 未运行，尝试启动...")
                return self._launch_frida_server()

        except Exception as e:
            self.log(f"❌ Frida Server 启动失败: {e}")
            return False

    def _launch_frida_server(self):
        """启动外部 Frida Server"""
        try:
            # 查找 Frida Server 可执行文件
            possible_paths = [
                './frida-server',
                './frida-server-arm64',
                '/usr/local/bin/frida-server',
                '/usr/bin/frida-server'
            ]

            server_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    server_path = path
                    break

            if not server_path:
                self.log("❌ 未找到 Frida Server 可执行文件")
                self.log("   请下载并放置 frida-server 到当前目录")
                return False

            self.log(f"🚀 启动 Frida Server: {server_path}")

            # 启动 Frida Server
            self.server_process = subprocess.Popen(
                [server_path, '-D'],  # -D = daemon mode
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # 等待启动
            time.sleep(2)

            # 验证
            try:
                self.device = frida.get_usb_device(timeout=3)
                self.log("✅ Frida Server 启动成功")
                return True
            except:
                self.log("❌ Frida Server 启动失败")
                return False

        except Exception as e:
            self.log(f"❌ 启动 Frida Server 异常: {e}")
            return False

    def _connect_and_inject(self):
        """Connect Frida and inject script"""
        try:
            self.log("🔌 Connecting Frida device...")

            # 检查 Frida 是否可用
            if not FRIDA_AVAILABLE:
                self.log("⚠️ Frida not available, service will operate in limited mode")
                self.log("   Token monitoring will not be available")
                return False

            # 获取设备
            if self.device is None:
                if self.is_apk:
                    # APK 内部直接使用本地设备
                    self.device = frida.get_local_device()
                else:
                    self.device = frida.get_usb_device(timeout=5)

            self.log(f"✅ Device connected: {self.device}")

            # 附加到目标进程
            self.log(f"📱 附加到目标 APP: {self.target_package}")

            # 等待目标 APP 启动
            max_attempts = 10
            for attempt in range(max_attempts):
                try:
                    self.session = self.device.attach(self.target_package)
                    self.log("✅ 已附加到目标 APP")
                    break
                except frida.ProcessNotFoundError:
                    if attempt == max_attempts - 1:
                        self.log(f"❌ 目标 APP 未运行: {self.target_package}")
                        self.log("   请先启动目标 APP，然后重新启动服务")
                        return False
                    self.log(f"   等待目标 APP 启动 (第 {attempt + 1} 次)...")
                    time.sleep(3)
                except Exception as e:
                    self.log(f"❌ 附加失败: {e}")
                    return False

            # 加载 Frida 脚本
            script_path = self._get_script_path()
            if not script_path:
                return False

            with open(script_path, 'r', encoding='utf-8') as f:
                script_code = f.read()

            self.log("🔧 注入 Frida 脚本...")
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_frida_message)

            # 设置脚本选项（针对 ARM64 优化）
            script_options = {
                'runtime': 'v8'  # 使用 V8 运行时，更稳定
            }
            self.script.load(**script_options)

            self.log("✅ Frida 脚本注入成功")
            self.log("🎯 等待目标 APP 发送网络请求...")

            return True

        except Exception as e:
            self.log(f"❌ Frida 连接注入失败: {e}")
            import traceback
            self.log(traceback.format_exc()[:300])
            return False

    def _get_script_path(self):
        """获取 Frida 脚本路径"""
        try:
            # 尝试多种可能的路径
            possible_paths = [
                # APK 内部路径
                os.path.join(os.path.dirname(__file__), '..', 'frida_token_grabber.js'),
                os.path.join(os.path.dirname(__file__), '..', '..', 'frida_token_grabber.js'),
                # APK assets 路径
                '/data/user/0/com.graborder.graborder/files/app/frida_token_grabber.js',
                # 当前目录
                './frida_token_grabber.js',
                'frida_token_grabber.js'
            ]

            for path in possible_paths:
                if os.path.exists(path):
                    self.log(f"📄 找到 Frida 脚本: {path}")
                    return path

            self.log("❌ 未找到 Frida 脚本文件")
            self.log("   搜索路径:")
            for path in possible_paths:
                self.log(f"     - {path}")
            return None

        except Exception as e:
            self.log(f"❌ 获取脚本路径失败: {e}")
            return None

    def _on_frida_message(self, message, data):
        """处理 Frida 消息"""
        try:
            if message['type'] == 'send':
                payload = message['payload']

                if payload.get('type') == 'token_update':
                    token_data = payload.get('data', {})
                    self._update_token(token_data)

                elif payload.get('type') == 'debug':
                    debug_msg = payload.get('message', '')
                    self.log(f"🐛 Frida 调试: {debug_msg}")

                elif payload.get('type') == 'hook_success':
                    self.log("🎯 Frida Hook 成功注入")

                elif payload.get('type') == 'hook_error':
                    error_msg = payload.get('message', '')
                    self.log(f"⚠️ Frida Hook 错误: {error_msg}")

            elif message['type'] == 'error':
                error_desc = message.get('description', 'Unknown error')
                self.log(f"⚠️ Frida 脚本错误: {error_desc}")

        except Exception as e:
            self.log(f"❌ 处理 Frida 消息失败: {e}")

    def _update_token(self, data):
        """更新 Token"""
        try:
            changed = False

            token = data.get('token', '').replace('Bearer ', '').strip()
            club_id = data.get('club_id', '')
            role_id = data.get('role_id', '')
            tenant_id = data.get('tenant_id', '')

            if token and token != self.token_data['token']:
                self.token_data['token'] = token
                changed = True
                self.log(f"🎯 Token 已更新: {token[:20]}...")

            if club_id and str(club_id) != self.token_data['club_id']:
                self.token_data['club_id'] = str(club_id)
                changed = True
                self.log(f"   Club-ID: {club_id}")

            if role_id and str(role_id) != self.token_data['role_id']:
                self.token_data['role_id'] = str(role_id)
                changed = True
                self.log(f"   Role-ID: {role_id}")

            if tenant_id and str(tenant_id) != self.token_data['tenant_id']:
                self.token_data['tenant_id'] = str(tenant_id)
                changed = True
                self.log(f"   Tenant-ID: {tenant_id}")

            if changed:
                self.token_data['timestamp'] = int(time.time())

                # 回调通知
                if self.token_callback:
                    self.token_callback(self.token_data)

        except Exception as e:
            self.log(f"❌ 更新 Token 失败: {e}")

    def stop(self):
        """停止服务"""
        self.running = False
        self.log("⏹️ 停止纯 APK Frida 服务")

        # 停止 Frida 脚本
        if self.script:
            try:
                self.script.unload()
                self.log("✅ Frida 脚本已卸载")
            except Exception as e:
                self.log(f"⚠️ 卸载脚本失败: {e}")

        # 分离会话
        if self.session:
            try:
                self.session.detach()
                self.log("✅ Frida 会话已分离")
            except Exception as e:
                self.log(f"⚠️ 分离会话失败: {e}")

        # 停止 Frida Server（如果是我们启动的）
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
                self.log("✅ Frida Server 已停止")
            except Exception as e:
                self.log(f"⚠️ 停止 Frida Server 失败: {e}")

    def get_token_data(self):
        """获取当前 Token 数据"""
        return self.token_data.copy()

    def get_status(self):
        """获取服务状态"""
        return {
            'running': self.running,
            'frida_available': FRIDA_AVAILABLE,
            'is_apk': self.is_apk,
            'device_connected': self.device is not None,
            'session_attached': self.session is not None,
            'script_loaded': self.script is not None,
            'token_data': self.token_data
        }

    def log(self, message):
        """输出日志"""
        if self.log_callback:
            self.log_callback(message)
        else:
            timestamp = time.strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")


# 兼容性函数
def create_frida_service(target_package="com.dys.shzs", log_callback=None):
    """
    创建 Frida 服务实例
    自动选择最适合的实现
    """
    return FridaAPKService(target_package=target_package, log_callback=log_callback)


# 测试函数
def test_frida_apk():
    """测试函数"""
    print("🧪 测试纯 APK Frida 服务")

    service = FridaAPKService(log_callback=print)

    # 检查状态
    status = service.get_status()
    print("📊 服务状态:")
    for key, value in status.items():
        if key != 'token_data':
            print(f"   {key}: {value}")

    # 尝试启动
    print("\n🚀 尝试启动服务...")
    if service.start():
        print("✅ 服务启动成功")

        # 等待一段时间
        time.sleep(5)

        # 停止服务
        service.stop()
        print("✅ 服务已停止")
    else:
        print("❌ 服务启动失败")


if __name__ == '__main__':
    test_frida_apk()
