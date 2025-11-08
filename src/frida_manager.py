#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida 管理器 - 纯手机端
自动启动和管理 Frida Server
"""

import os
import sys
import time
import subprocess
import shutil
from pathlib import Path

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


class FridaManager:
    """Frida Server 管理器（手机端）"""
    
    def __init__(self, log_callback=None):
        """
        初始化
        
        Args:
            log_callback: 日志回调函数
        """
        self.log_callback = log_callback
        
        # Frida Server 路径
        self.server_source = None  # APK assets 中的路径
        self.server_dest = "/data/local/tmp/frida-server"
        
        # 状态
        self.is_running = False
        self.has_root = False
    
    def check_root(self):
        """检查 Root 权限"""
        try:
            self.log("🔍 检查 Root 权限...")
            
            result = subprocess.run(
                ['su', '-c', 'id'],
                capture_output=True,
                timeout=5
            )
            
            output = result.stdout.decode('utf-8', errors='ignore')
            
            if 'uid=0' in output:
                self.has_root = True
                self.log("✅ 已获取 Root 权限")
                return True
            else:
                self.has_root = False
                self.log("❌ 未获取 Root 权限")
                return False
                
        except subprocess.TimeoutExpired:
            self.log("⚠️ Root 权限请求超时（可能需要手动授权）")
            return False
        except Exception as e:
            self.log(f"❌ Root 权限检查失败: {e}")
            return False
    
    def request_root(self):
        """请求 Root 权限"""
        try:
            self.log("📋 请求 Root 权限...")
            self.log("   请在弹出窗口中点击'授权'")
            
            # 触发 Root 授权对话框
            result = subprocess.run(
                ['su', '-c', 'echo "Root test"'],
                capture_output=True,
                timeout=30  # 给用户 30 秒授权时间
            )
            
            if result.returncode == 0:
                self.has_root = True
                self.log("✅ Root 权限已授予")
                return True
            else:
                self.log("❌ Root 权限被拒绝")
                return False
                
        except subprocess.TimeoutExpired:
            self.log("⚠️ Root 授权超时")
            return False
        except Exception as e:
            self.log(f"❌ Root 权限请求失败: {e}")
            return False
    
    def extract_frida_server(self):
        """提取 Frida Server"""
        try:
            self.log("📦 提取 Frida Server...")
            
            # 检测 Android 环境
            try:
                from jnius import autoclass
                PythonActivity = autoclass('org.kivy.android.PythonActivity')
                activity = PythonActivity.mActivity
                
                # 从 assets 复制
                assets_path = activity.getFilesDir().getAbsolutePath()
                possible_paths = [
                    os.path.join(assets_path, 'frida-server'),
                    os.path.join(assets_path, 'assets', 'frida-server-arm64'),
                    'assets/frida-server-arm64',
                    './frida-server',
                ]
                
                for path in possible_paths:
                    if os.path.exists(path):
                        self.server_source = path
                        self.log(f"✅ 找到 Frida Server: {path}")
                        break
                
                if not self.server_source:
                    self.log("⚠️ 未找到 Frida Server，将尝试从网络下载")
                    return self.download_frida_server()
                    
            except ImportError:
                # PC 环境
                self.log("⚠️ 非 Android 环境")
                return False
            
            # 复制到系统目录
            if not self.has_root:
                self.log("❌ 需要 Root 权限才能提取 Frida Server")
                return False
            
            # 先复制到临时位置
            temp_path = "/sdcard/frida-server-temp"
            
            try:
                shutil.copy2(self.server_source, temp_path)
                self.log("✅ 已复制到临时位置")
            except Exception as e:
                self.log(f"❌ 复制失败: {e}")
                return False
            
            # 使用 Root 权限移动到目标位置
            commands = [
                f'cp {temp_path} {self.server_dest}',
                f'chmod 755 {self.server_dest}',
                f'rm {temp_path}'
            ]
            
            for cmd in commands:
                result = subprocess.run(
                    ['su', '-c', cmd],
                    capture_output=True,
                    timeout=10
                )
                
                if result.returncode != 0:
                    self.log(f"⚠️ 命令执行失败: {cmd}")
                    self.log(f"   {result.stderr.decode('utf-8', errors='ignore')}")
            
            # 验证
            result = subprocess.run(
                ['su', '-c', f'ls -l {self.server_dest}'],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode == 0:
                self.log("✅ Frida Server 提取成功")
                return True
            else:
                self.log("❌ Frida Server 提取失败")
                return False
                
        except Exception as e:
            self.log(f"❌ 提取 Frida Server 失败: {e}")
            import traceback
            self.log(traceback.format_exc()[:200])
            return False
    
    def download_frida_server(self):
        """下载 Frida Server（备用方案）"""
        try:
            self.log("📥 从网络下载 Frida Server...")
            self.log("   (首次需要几分钟)")
            
            # 检测架构
            result = subprocess.run(
                ['getprop', 'ro.product.cpu.abi'],
                capture_output=True
            )
            
            arch = result.stdout.decode().strip()
            
            if 'arm64' in arch:
                arch_name = 'arm64'
            elif 'armeabi' in arch:
                arch_name = 'arm'
            else:
                self.log(f"⚠️ 未知架构: {arch}")
                return False
            
            # 下载 URL
            version = "16.1.8"
            url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{arch_name}.xz"
            
            self.log(f"   下载: frida-server-{version}-android-{arch_name}")
            
            # TODO: 实现下载逻辑
            # 这里需要实现实际的下载功能
            
            self.log("⚠️ 自动下载功能未实现")
            self.log("   请手动安装 Frida Server 或使用完整 APK")
            
            return False
            
        except Exception as e:
            self.log(f"❌ 下载失败: {e}")
            return False
    
    def start_frida_server(self):
        """启动 Frida Server"""
        try:
            # 检查 Root
            if not self.has_root:
                if not self.check_root():
                    if not self.request_root():
                        self.log("❌ 需要 Root 权限才能启动 Frida Server")
                        return False
            
            # 检查是否已运行
            if self.check_frida_running():
                self.log("✅ Frida Server 已在运行")
                self.is_running = True
                return True
            
            # 检查 Frida Server 是否存在
            result = subprocess.run(
                ['su', '-c', f'ls {self.server_dest}'],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode != 0:
                self.log("⚠️ Frida Server 不存在，开始提取...")
                if not self.extract_frida_server():
                    return False
            
            # 启动 Frida Server
            self.log("🚀 启动 Frida Server...")
            
            subprocess.Popen(
                ['su', '-c', f'{self.server_dest} &'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # 等待启动
            self.log("   等待启动...")
            time.sleep(2)
            
            # 验证
            if self.check_frida_running():
                self.is_running = True
                self.log("✅ Frida Server 启动成功")
                return True
            else:
                self.log("❌ Frida Server 启动失败")
                return False
                
        except Exception as e:
            self.log(f"❌ 启动失败: {e}")
            import traceback
            self.log(traceback.format_exc()[:200])
            return False
    
    def stop_frida_server(self):
        """停止 Frida Server"""
        try:
            if not self.has_root:
                self.log("⚠️ 需要 Root 权限才能停止 Frida Server")
                return False
            
            self.log("⏹️ 停止 Frida Server...")
            
            subprocess.run(
                ['su', '-c', 'killall frida-server'],
                timeout=5
            )
            
            time.sleep(1)
            
            if not self.check_frida_running():
                self.is_running = False
                self.log("✅ Frida Server 已停止")
                return True
            else:
                self.log("⚠️ Frida Server 可能仍在运行")
                return False
                
        except Exception as e:
            self.log(f"❌ 停止失败: {e}")
            return False
    
    def check_frida_running(self):
        """检查 Frida Server 是否运行"""
        try:
            result = subprocess.run(
                ['su', '-c', 'ps -ef | grep frida-server | grep -v grep'],
                capture_output=True,
                timeout=5
            )
            
            is_running = 'frida-server' in result.stdout.decode('utf-8', errors='ignore')
            self.is_running = is_running
            
            return is_running
            
        except Exception as e:
            return False
    
    def get_status(self):
        """获取状态"""
        return {
            'has_root': self.has_root,
            'is_running': self.is_running,
            'server_path': self.server_dest
        }
    
    def log(self, message):
        """输出日志"""
        if self.log_callback:
            self.log_callback(message)
        else:
            print(message)

