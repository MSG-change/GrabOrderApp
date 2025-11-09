#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida Token 获取服务
通过 Frida Hook 目标 APP 自动获取 Token
"""

import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    print("⚠️ Frida 未安装，使用文件监控模式")


class FridaTokenService:
    """Frida Token 获取服务"""
    
    def __init__(self, target_package="com.your.target.app", log_callback=None):
        """
        初始化
        
        Args:
            target_package: 目标 APP 包名
            log_callback: 日志回调函数
        """
        self.target_package = target_package
        self.log_callback = log_callback
        
        self.running = False
        self.thread = None
        
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
        
        # Frida 相关
        self.device = None
        self.session = None
        self.script = None
        
        # Token 文件路径
        self.token_file = "/sdcard/grab_order_token.json"
        
        # 使用模式
        self.use_frida = FRIDA_AVAILABLE
        self.use_file_watch = True  # 始终启用文件监控作为备用
    
    def set_token_callback(self, callback):
        """设置 Token 更新回调"""
        self.token_callback = callback
    
    def start(self):
        """启动服务"""
        if self.running:
            self.log("⚠️ Frida 服务已在运行中")
            return False
        
        self.running = True
        
        # 尝试启动 Frida Hook
        if self.use_frida:
            success = self._start_frida_hook()
            if not success:
                self.log("⚠️ Frida Hook 启动失败，切换到文件监控模式")
                self.use_frida = False
        
        # 启动文件监控（备用方案）
        if self.use_file_watch:
            self.thread = threading.Thread(target=self._watch_token_file, daemon=True)
            self.thread.start()
            self.log("✅ Token 文件监控已启动")
        
        return True
    
    def stop(self):
        """停止服务"""
        self.running = False
        
        if self.script:
            try:
                self.script.unload()
            except:
                pass
        
        if self.session:
            try:
                self.session.detach()
            except:
                pass
        
        if self.thread:
            self.thread.join(timeout=2)
        
        self.log("⏹️ Frida 服务已停止")
    
    def _start_frida_hook(self):
        """启动 Frida Hook"""
        try:
            self.log("🔧 正在连接 Frida...")
            
            # 获取 USB 设备
            self.device = frida.get_usb_device(timeout=5)
            self.log(f"✅ 已连接设备: {self.device}")
            
            # 检查目标 APP 是否运行
            try:
                # 尝试附加到运行中的进程
                self.log(f"📱 正在附加到: {self.target_package}")
                self.session = self.device.attach(self.target_package)
                self.log("✅ 已附加到目标 APP")
            except frida.ProcessNotFoundError:
                self.log(f"⚠️ 目标 APP 未运行: {self.target_package}")
                self.log("   请先启动目标 APP，然后重新启动此服务")
                return False
            
            # 加载 Frida 脚本
            script_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'frida_token_grabber.js'
            )
            
            if not os.path.exists(script_path):
                self.log(f"❌ Frida 脚本不存在: {script_path}")
                return False
            
            with open(script_path, 'r', encoding='utf-8') as f:
                script_code = f.read()
            
            self.log("🔧 正在加载 Frida 脚本...")
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_frida_message)
            self.script.load()
            
            self.log("✅ Frida Hook 已激活")
            self.log("   等待目标 APP 发送网络请求...")
            
            return True
            
        except Exception as e:
            self.log(f"❌ Frida Hook 启动失败: {e}")
            import traceback
            self.log(traceback.format_exc()[:200])
            return False
    
    def _on_frida_message(self, message, data):
        """处理 Frida 消息"""
        try:
            if message['type'] == 'send':
                payload = message['payload']
                
                if payload.get('type') == 'token_update':
                    # Token 更新
                    token_data = payload.get('data', {})
                    self._update_token(token_data)
                    
            elif message['type'] == 'error':
                self.log(f"⚠️ Frida 错误: {message.get('description', 'Unknown')}")
                
        except Exception as e:
            self.log(f"❌ 处理 Frida 消息失败: {e}")
    
    def _watch_token_file(self):
        """监控 Token 文件（备用方案）"""
        self.log("📂 Token 文件监控已启动")
        
        last_mtime = 0
        
        while self.running:
            try:
                if os.path.exists(self.token_file):
                    mtime = os.path.getmtime(self.token_file)
                    
                    if mtime > last_mtime:
                        last_mtime = mtime
                        
                        # 读取文件
                        with open(self.token_file, 'r') as f:
                            data = json.load(f)
                        
                        # 更新 Token
                        if data.get('token'):
                            self._update_token(data)
                
            except Exception as e:
                pass  # 静默错误，避免刷屏
            
            time.sleep(0.5)  # 每 0.5 秒检查一次
    
    def _update_token(self, data):
        """更新 Token"""
        # 检查是否有变化
        changed = False
        
        token = data.get('token', '').replace('Bearer ', '').strip()
        club_id = data.get('club_id', '')
        role_id = data.get('role_id', '')
        tenant_id = data.get('tenant_id', '')
        
        if token and token != self.token_data['token']:
            self.token_data['token'] = token
            changed = True
            self.log(f"🎯 Token 已更新: {token[:20]}...")
        
        if club_id and club_id != self.token_data['club_id']:
            self.token_data['club_id'] = str(club_id)
            changed = True
            self.log(f"   Club-ID: {club_id}")
        
        if role_id and role_id != self.token_data['role_id']:
            self.token_data['role_id'] = str(role_id)
            changed = True
            self.log(f"   Role-ID: {role_id}")
        
        if tenant_id and tenant_id != self.token_data['tenant_id']:
            self.token_data['tenant_id'] = str(tenant_id)
            changed = True
            self.log(f"   Tenant-ID: {tenant_id}")
        
        if changed:
            self.token_data['timestamp'] = int(time.time())
            
            # 回调通知
            if self.token_callback:
                self.token_callback(self.token_data)
    
    def get_token_data(self):
        """获取当前 Token 数据"""
        return self.token_data.copy()
    
    def log(self, message):
        """输出日志"""
        if self.log_callback:
            self.log_callback(message)
        else:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")


class FridaTokenServiceSimple:
    """简化版 Frida Token 服务（仅文件监控）"""
    
    def __init__(self, log_callback=None):
        """初始化"""
        self.log_callback = log_callback
        self.running = False
        self.thread = None
        
        self.token_data = {
            'token': '',
            'club_id': '',
            'role_id': '',
            'tenant_id': '',
            'timestamp': 0
        }
        
        self.token_callback = None
        self.token_file = "/sdcard/grab_order_token.json"
        
        # Try to start external Frida server if available
        self._try_start_external_frida()
    
    def _try_start_external_frida(self):
        """Try to start external Frida server for MuMu emulator"""
        try:
            # Check if we're in Android environment
            try:
                import android
                is_android = True
            except ImportError:
                is_android = False
            
            if not is_android:
                return  # Not in Android, skip
            
            # Check if Frida server is already running
            result = subprocess.run(['ps'], capture_output=True, text=True, timeout=2)
            if 'frida-server' in result.stdout:
                self.log("External Frida server already running")
                return
            
            # Try to start Frida server if it exists
            frida_paths = [
                '/data/local/tmp/frida-server',
                '/data/local/tmp/frida-server-arm64',
                '/system/bin/frida-server'
            ]
            
            for path in frida_paths:
                if os.path.exists(path):
                    try:
                        # Start in background
                        subprocess.Popen([path, '-D'], 
                                       stdout=subprocess.DEVNULL, 
                                       stderr=subprocess.DEVNULL)
                        self.log(f"Started external Frida server: {path}")
                        time.sleep(1)  # Give it time to start
                        return
                    except Exception as e:
                        self.log(f"Failed to start {path}: {e}")
            
            self.log("No external Frida server found, using file monitoring only")
            
        except Exception as e:
            self.log(f"External Frida check error: {e}")
    
    def set_token_callback(self, callback):
        """设置回调"""
        self.token_callback = callback
    
    def start(self):
        """启动"""
        if self.running:
            return False
        
        self.running = True
        self.thread = threading.Thread(target=self._watch_file, daemon=True)
        self.thread.start()
        
        self.log("✅ Token 监控已启动")
        self.log(f"   监控文件: {self.token_file}")
        self.log("   请确保 Frida 脚本在 PC 或其他终端运行")
        
        return True
    
    def stop(self):
        """停止"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        self.log("⏹️ Token 监控已停止")
    
    def _watch_file(self):
        """监控文件"""
        last_mtime = 0
        
        while self.running:
            try:
                if os.path.exists(self.token_file):
                    mtime = os.path.getmtime(self.token_file)
                    
                    if mtime > last_mtime:
                        last_mtime = mtime
                        
                        with open(self.token_file, 'r') as f:
                            data = json.load(f)
                        
                        if data.get('token'):
                            self._update_token(data)
            except:
                pass
            
            time.sleep(0.5)
    
    def _update_token(self, data):
        """更新 Token"""
        changed = False
        
        token = data.get('token', '').replace('Bearer ', '').strip()
        if token and token != self.token_data['token']:
            self.token_data['token'] = token
            changed = True
            self.log(f"🎯 Token: {token[:20]}...")
        
        for key in ['club_id', 'role_id', 'tenant_id']:
            value = str(data.get(key, ''))
            if value and value != self.token_data[key]:
                self.token_data[key] = value
                changed = True
                self.log(f"   {key}: {value}")
        
        if changed:
            self.token_data['timestamp'] = int(time.time())
            if self.token_callback:
                self.token_callback(self.token_data)
    
    def get_token_data(self):
        """获取 Token"""
        return self.token_data.copy()
    
    def log(self, message):
        """日志"""
        if self.log_callback:
            self.log_callback(message)
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

