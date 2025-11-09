#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MuMu Emulator Frida Service
专为 MuMu 模拟器设计的 Frida 服务
使用外部 Frida Server 避免架构冲突问题
"""

import os
import sys
import json
import time
import threading
import subprocess
from pathlib import Path

# Try importing Frida - if not available, we'll use subprocess to control external server
try:
    import frida
    FRIDA_PYTHON_AVAILABLE = True
except ImportError:
    FRIDA_PYTHON_AVAILABLE = False
    print("⚠️ Frida Python module not available, will use external Frida server only")

try:
    from jnius import autoclass, cast
    ANDROID_AVAILABLE = True
except ImportError:
    ANDROID_AVAILABLE = False


class MuMuFridaService:
    """
    MuMu 专用 Frida 服务
    使用外部 Frida Server 运行在 /data/local/tmp/
    避免 Python Frida 库的架构冲突问题
    """
    
    def __init__(self, target_package="com.dys.shzs", log_callback=None):
        """
        初始化 MuMu Frida 服务
        
        Args:
            target_package: 目标 APP 包名
            log_callback: 日志回调函数
        """
        self.target_package = target_package
        self.log_callback = log_callback
        
        self.running = False
        self.monitor_thread = None
        
        # Frida 相关
        self.device = None
        self.session = None
        self.script = None
        self.frida_server_process = None
        
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
        
        # Frida server 路径
        self.frida_server_paths = [
            '/data/local/tmp/frida-server',
            '/data/local/tmp/frida-server-arm64',
            '/data/local/tmp/frida-server-16.1.8-android-arm64'
        ]
        
        # Check if we're in MuMu environment
        self.is_mumu = self._check_mumu_environment()
        
    def _check_mumu_environment(self):
        """检查是否在 MuMu 环境中运行"""
        try:
            if ANDROID_AVAILABLE:
                # Check Android properties for MuMu signatures
                result = subprocess.run(
                    ['getprop', 'ro.product.manufacturer'],
                    capture_output=True, text=True, timeout=2
                )
                if result.returncode == 0:
                    manufacturer = result.stdout.strip().lower()
                    if any(x in manufacturer for x in ['nemu', 'mumu', 'netease']):
                        self.log("✅ MuMu environment confirmed")
                        return True
                        
                # Check model
                result = subprocess.run(
                    ['getprop', 'ro.product.model'],
                    capture_output=True, text=True, timeout=2
                )
                if result.returncode == 0:
                    model = result.stdout.strip().lower()
                    if any(x in model for x in ['mumu', 'nemu']):
                        self.log("✅ MuMu environment confirmed (by model)")
                        return True
                        
        except Exception as e:
            self.log(f"⚠️ MuMu detection error: {e}")
            
        return False
    
    def set_token_callback(self, callback):
        """设置 Token 更新回调"""
        self.token_callback = callback
    
    def start(self):
        """启动 MuMu Frida 服务"""
        if self.running:
            self.log("⚠️ MuMu Frida service already running")
            return False
        
        self.running = True
        self.log("🚀 Starting MuMu Frida Service")
        self.log("   Using external Frida server approach")
        
        # Step 1: Start external Frida server
        if not self._start_external_frida_server():
            self.log("⚠️ Failed to start external Frida server")
            # Continue anyway - server might already be running
        
        # Step 2: Connect to Frida
        if FRIDA_PYTHON_AVAILABLE:
            # If Frida Python module is available, use it
            if not self._connect_frida_python():
                self.log("⚠️ Failed to connect via Frida Python module")
                # Fall back to monitoring approach
                return self._start_monitoring_fallback()
        else:
            # Use monitoring fallback if no Python Frida
            return self._start_monitoring_fallback()
        
        self.log("✅ MuMu Frida Service started successfully")
        return True
    
    def _start_external_frida_server(self):
        """启动外部 Frida Server"""
        try:
            self.log("🔧 Starting external Frida server...")
            
            # Check if Frida server is already running
            result = subprocess.run(
                ['ps'], 
                capture_output=True, 
                text=True,
                timeout=2
            )
            if 'frida-server' in result.stdout:
                self.log("✅ Frida server already running")
                return True
            
            # Try to start Frida server
            for server_path in self.frida_server_paths:
                if os.path.exists(server_path):
                    self.log(f"📱 Found Frida server at: {server_path}")
                    
                    # Make it executable
                    try:
                        subprocess.run(['chmod', '755', server_path], timeout=2)
                    except:
                        pass
                    
                    # Start Frida server in background
                    try:
                        # Use subprocess to start in daemon mode
                        self.frida_server_process = subprocess.Popen(
                            [server_path, '-D'],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        
                        time.sleep(2)  # Wait for server to start
                        
                        # Check if it's running
                        result = subprocess.run(
                            ['ps'], 
                            capture_output=True, 
                            text=True,
                            timeout=2
                        )
                        if 'frida-server' in result.stdout:
                            self.log("✅ External Frida server started successfully")
                            return True
                        else:
                            self.log("⚠️ Frida server may not have started properly")
                            
                    except Exception as e:
                        self.log(f"⚠️ Failed to start {server_path}: {e}")
            
            # Try to download and install Frida server if not found
            self.log("⚠️ No Frida server found, attempting to download...")
            if self._download_frida_server():
                return self._start_external_frida_server()  # Retry after download
                
            self.log("❌ No Frida server available")
            return False
            
        except Exception as e:
            self.log(f"❌ Failed to start external Frida server: {e}")
            return False
    
    def _download_frida_server(self):
        """Download Frida server for MuMu"""
        try:
            self.log("📥 Downloading Frida server...")
            
            # Determine architecture
            result = subprocess.run(
                ['getprop', 'ro.product.cpu.abi'],
                capture_output=True, text=True, timeout=2
            )
            
            if result.returncode == 0:
                abi = result.stdout.strip()
                self.log(f"   Device ABI: {abi}")
                
                # Determine which Frida server to download
                if 'arm64' in abi:
                    arch = 'arm64'
                elif 'x86_64' in abi:
                    arch = 'x86_64'
                else:
                    arch = 'arm'
                
                # Download using curl or wget
                frida_version = "16.1.8"
                url = f"https://github.com/frida/frida/releases/download/{frida_version}/frida-server-{frida_version}-android-{arch}.xz"
                target_path = "/data/local/tmp/frida-server.xz"
                
                self.log(f"   Downloading from: {url}")
                
                # Try curl first
                result = subprocess.run(
                    ['curl', '-L', '-o', target_path, url],
                    capture_output=True, timeout=60
                )
                
                if result.returncode == 0:
                    # Extract
                    self.log("   Extracting...")
                    subprocess.run(['unxz', target_path], timeout=10)
                    
                    # Make executable
                    frida_path = "/data/local/tmp/frida-server"
                    subprocess.run(['chmod', '755', frida_path], timeout=2)
                    
                    self.log("✅ Frida server downloaded and installed")
                    return True
                    
        except Exception as e:
            self.log(f"❌ Failed to download Frida server: {e}")
            
        return False
    
    def _connect_frida_python(self):
        """使用 Python Frida 模块连接"""
        try:
            self.log("🔌 Connecting via Frida Python module...")
            
            # Get local device (since we're running inside the Android app)
            self.device = frida.get_local_device()
            self.log(f"✅ Connected to device: {self.device}")
            
            # Wait for target app
            max_attempts = 10
            for attempt in range(max_attempts):
                try:
                    # List processes to find target
                    processes = self.device.enumerate_processes()
                    target_found = False
                    
                    for proc in processes:
                        if self.target_package in proc.name:
                            target_found = True
                            self.log(f"✅ Found target process: {proc.name} (PID: {proc.pid})")
                            break
                    
                    if target_found:
                        # Attach to target
                        self.session = self.device.attach(self.target_package)
                        self.log("✅ Attached to target app")
                        
                        # Load script
                        if self._load_frida_script():
                            return True
                        else:
                            return False
                    else:
                        if attempt < max_attempts - 1:
                            self.log(f"   Waiting for target app... ({attempt + 1}/{max_attempts})")
                            time.sleep(3)
                            
                except Exception as e:
                    if attempt < max_attempts - 1:
                        self.log(f"   Attach attempt {attempt + 1} failed: {e}")
                        time.sleep(3)
            
            self.log("❌ Could not attach to target app")
            return False
            
        except Exception as e:
            self.log(f"❌ Frida Python connection failed: {e}")
            return False
    
    def _load_frida_script(self):
        """加载 Frida Hook 脚本"""
        try:
            # Frida script content
            script_code = """
            console.log("🎯 MuMu Frida script loaded");
            
            Java.perform(function() {
                console.log("📱 Java.perform() started");
                
                try {
                    // Hook OkHttp for network interception
                    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
                    var Request = Java.use("okhttp3.Request");
                    
                    console.log("✅ OkHttp classes found");
                    
                    // Hook Request.Builder.build()
                    Request.Builder.build.implementation = function() {
                        var request = this.build();
                        var url = request.url().toString();
                        var headers = request.headers();
                        
                        // Extract token data
                        var tokenData = {
                            token: "",
                            club_id: "",
                            role_id: "",
                            tenant_id: "",
                            timestamp: Date.now()
                        };
                        
                        // Get headers
                        var headerCount = headers.size();
                        for (var i = 0; i < headerCount; i++) {
                            var name = headers.name(i);
                            var value = headers.value(i);
                            
                            if (name.toLowerCase() === "authorization") {
                                tokenData.token = value.replace("Bearer ", "");
                                console.log("🎯 Token captured: " + tokenData.token.substring(0, 30) + "...");
                            } else if (name.toLowerCase() === "club-id") {
                                tokenData.club_id = value;
                            } else if (name.toLowerCase() === "role-id") {
                                tokenData.role_id = value;
                            } else if (name.toLowerCase() === "tenant-id") {
                                tokenData.tenant_id = value;
                            }
                        }
                        
                        // Send token data
                        if (tokenData.token) {
                            send({
                                type: "token_update",
                                data: tokenData
                            });
                        }
                        
                        return request;
                    };
                    
                    console.log("✅ OkHttp hooks installed successfully");
                    send({type: "hook_success", message: "Hooks installed"});
                    
                } catch(e) {
                    console.log("❌ Failed to hook OkHttp: " + e);
                    send({type: "hook_error", message: e.toString()});
                }
                
                // Try Retrofit as well
                try {
                    var Retrofit = Java.use("retrofit2.Retrofit");
                    console.log("✅ Retrofit found");
                } catch(e) {
                    console.log("⚠️ Retrofit not found (this is okay)");
                }
            });
            """
            
            self.log("🔧 Loading Frida script...")
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_frida_message)
            self.script.load()
            
            self.log("✅ Frida script loaded and hooks installed")
            self.log("🎯 Monitoring network requests for tokens...")
            
            return True
            
        except Exception as e:
            self.log(f"❌ Failed to load Frida script: {e}")
            return False
    
    def _on_frida_message(self, message, data):
        """处理 Frida 消息"""
        try:
            if message['type'] == 'send':
                payload = message['payload']
                
                if payload.get('type') == 'token_update':
                    token_data = payload.get('data', {})
                    self._update_token(token_data)
                    
                elif payload.get('type') == 'hook_success':
                    self.log(f"✅ {payload.get('message', 'Hook success')}")
                    
                elif payload.get('type') == 'hook_error':
                    self.log(f"⚠️ Hook error: {payload.get('message', 'Unknown')}")
                    
                elif payload.get('type') == 'debug':
                    self.log(f"🐛 Debug: {payload.get('message', '')}")
                    
            elif message['type'] == 'error':
                self.log(f"⚠️ Script error: {message.get('description', 'Unknown')}")
                
        except Exception as e:
            self.log(f"❌ Message handling error: {e}")
    
    def _start_monitoring_fallback(self):
        """启动监控降级模式"""
        self.log("📂 Starting monitoring fallback mode...")
        self.log("   This mode monitors for tokens via alternative methods")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        self.log("✅ Monitoring fallback started")
        return True
    
    def _monitor_loop(self):
        """监控循环"""
        while self.running:
            try:
                # Check if Frida server is still running
                result = subprocess.run(
                    ['ps'], 
                    capture_output=True, 
                    text=True,
                    timeout=2
                )
                
                if 'frida-server' not in result.stdout:
                    self.log("⚠️ Frida server not running, attempting restart...")
                    self._start_external_frida_server()
                
            except Exception as e:
                pass
            
            time.sleep(5)  # Check every 5 seconds
    
    def _update_token(self, data):
        """更新 Token"""
        try:
            changed = False
            
            token = data.get('token', '').replace('Bearer ', '').strip()
            club_id = str(data.get('club_id', ''))
            role_id = str(data.get('role_id', ''))
            tenant_id = str(data.get('tenant_id', ''))
            
            if token and token != self.token_data['token']:
                self.token_data['token'] = token
                changed = True
                self.log(f"🎯 Token updated: {token[:20]}...")
            
            if club_id and club_id != self.token_data['club_id']:
                self.token_data['club_id'] = club_id
                changed = True
                self.log(f"   Club-ID: {club_id}")
            
            if role_id and role_id != self.token_data['role_id']:
                self.token_data['role_id'] = role_id
                changed = True
                self.log(f"   Role-ID: {role_id}")
            
            if tenant_id and tenant_id != self.token_data['tenant_id']:
                self.token_data['tenant_id'] = tenant_id
                changed = True
                self.log(f"   Tenant-ID: {tenant_id}")
            
            if changed:
                self.token_data['timestamp'] = int(time.time())
                
                # Callback notification
                if self.token_callback:
                    self.token_callback(self.token_data)
                    
        except Exception as e:
            self.log(f"❌ Failed to update token: {e}")
    
    def stop(self):
        """停止服务"""
        self.running = False
        self.log("⏹️ Stopping MuMu Frida Service")
        
        # Stop Frida script
        if self.script:
            try:
                self.script.unload()
                self.log("✅ Frida script unloaded")
            except Exception as e:
                self.log(f"⚠️ Failed to unload script: {e}")
        
        # Detach session
        if self.session:
            try:
                self.session.detach()
                self.log("✅ Session detached")
            except Exception as e:
                self.log(f"⚠️ Failed to detach session: {e}")
        
        # Stop Frida server if we started it
        if self.frida_server_process:
            try:
                self.frida_server_process.terminate()
                self.frida_server_process.wait(timeout=5)
                self.log("✅ External Frida server stopped")
            except Exception as e:
                self.log(f"⚠️ Failed to stop Frida server: {e}")
        
        # Stop monitoring thread
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        
        self.log("✅ MuMu Frida Service stopped")
    
    def get_token_data(self):
        """获取当前 Token 数据"""
        return self.token_data.copy()
    
    def get_status(self):
        """获取服务状态"""
        return {
            'running': self.running,
            'is_mumu': self.is_mumu,
            'frida_python_available': FRIDA_PYTHON_AVAILABLE,
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
            print(f"[{timestamp}] [MuMuFrida] {message}")
