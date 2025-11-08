#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Token 捕获服务
通过本地 VPN 抓包自动提取 Authorization Token

注意：Android VPN需要系统权限，实现较为复杂。
当前版本使用简化的HTTP拦截方式。
"""

import re
import threading
import time
from queue import Queue

try:
    from jnius import autoclass, cast, PythonJavaClass, java_method
    from android import mActivity
    ANDROID = True
except ImportError:
    ANDROID = False


class VPNTokenCapture:
    """VPN Token 捕获器（简化版本）"""
    
    def __init__(self, token_callback=None, log_callback=None):
        """
        初始化
        
        Args:
            token_callback: Token 捕获回调 (token, headers)
            log_callback: 日志回调
        """
        self.token_callback = token_callback
        self.log_callback = log_callback
        
        self.running = False
        self.vpn_interface = None
        self.packet_queue = Queue()
        
        # 目标域名（抢单服务器）
        self.target_host = "dysh.dyswl.com"
        
        # Token 正则 (兼容各种格式)
        self.token_pattern = re.compile(
            r'(?:authorization|Authorization):\s*(?:Bearer\s+)?([a-zA-Z0-9\.\-_]+)',
            re.IGNORECASE
        )
        
        # 使用网络拦截方式（更简单可靠）
        self.intercept_thread = None
    
    def start_vpn(self):
        """启动 VPN/网络拦截服务"""
        if not ANDROID:
            self.log("⚠️ 非Android环境，VPN服务不可用")
            return False
        
        try:
            self.log("🔒 正在请求VPN权限...")
            
            # 准备VPN Intent
            Intent = autoclass('android.content.Intent')
            VpnService = autoclass('android.net.VpnService')
            
            # 请求VPN权限
            intent = VpnService.prepare(mActivity)
            
            if intent is not None:
                # 需要用户授权
                self.log("⚠️ 需要VPN权限，请在弹出窗口中点击确定")
                self.log("   注意：VPN权限是必需的，用于拦截网络流量")
                
                # 启动Activity等待用户授权
                mActivity.startActivityForResult(intent, 0)
                
                # 等待用户授权（最多等待10秒）
                self.log("⏳ 等待用户授权VPN权限...")
                for i in range(20):  # 20次 * 0.5秒 = 10秒
                    time.sleep(0.5)
                    # 再次检查权限
                    check_intent = VpnService.prepare(mActivity)
                    if check_intent is None:
                        self.log("✅ VPN权限已授予")
                        break
                    if i == 19:
                        self.log("⚠️ VPN权限授权超时，请手动授权")
                        return False
            else:
                self.log("✅ VPN权限已授予")
            
            # 尝试建立VPN连接
            success = self._establish_vpn()
            
            if success:
                # 启动数据包处理线程
                self.running = True
                self.intercept_thread = threading.Thread(
                    target=self._intercept_network_traffic,
                    daemon=True
                )
                self.intercept_thread.start()
                
                self.log("✅ VPN抓包服务已启动")
                return True
            else:
                self.log("⚠️ VPN连接建立失败，使用备用方案：手动输入Token")
                self.log("   您可以在应用中手动输入Token")
                return False
            
        except Exception as e:
            self.log(f"❌ VPN启动失败: {e}")
            import traceback
            self.log(traceback.format_exc())
            return False
    
    def _establish_vpn(self):
        """建立VPN连接"""
        try:
            self.log("📡 正在建立VPN隧道...")
            
            VpnService = autoclass('android.net.VpnService')
            Builder = autoclass('android.net.VpnService$Builder')
            ParcelFileDescriptor = autoclass('android.os.ParcelFileDescriptor')
            
            # 注意：VpnService.Builder需要在VpnService实例中创建
            # 但由于Python的限制，我们使用反射方式
            
            # 创建VPN Builder（需要在VpnService上下文中）
            # 这里使用一个workaround：通过ServiceContext创建
            
            try:
                # 方法1：尝试通过mActivity创建（可能失败）
                # 实际上，VpnService.Builder需要在VpnService实例中调用
                # 所以我们先尝试最简单的方式
                
                # 获取当前Context
                Context = autoclass('android.content.Context')
                
                # 由于Python for Android的限制，直接创建VPN比较复杂
                # 这里提供一个简化方案：使用网络拦截
                
                self.log("⚠️ 直接VPN创建受限，使用网络监控方式")
                self.log("   建议：手动输入Token或使用其他抓包工具")
                
                # 返回False，使用备用方案
                return False
                
            except Exception as e:
                self.log(f"⚠️ VPN Builder创建失败: {e}")
                return False
                
        except Exception as e:
            self.log(f"❌ 建立VPN失败: {e}")
            import traceback
            self.log(traceback.format_exc())
            return False
    
    def _intercept_network_traffic(self):
        """拦截网络流量（简化版本）"""
        """
        注意：真正的VPN数据包拦截需要：
        1. 建立VPN连接
        2. 读取/写入VPN文件描述符
        3. 解析IP/TCP/HTTP数据包
        4. 转发数据包以保持网络正常
        
        由于Android VPN API的限制和Python的复杂性，
        这个功能需要更深入的Java集成。
        
        当前实现：提供一个占位符，提示用户手动输入Token
        """
        self.log("📦 网络拦截线程已启动")
        self.log("⚠️ 注意：VPN数据包拦截功能需要更复杂的实现")
        self.log("   当前版本建议：")
        self.log("   1. 使用Charles/Fiddler等抓包工具获取Token")
        self.log("   2. 在应用中手动输入Token")
        self.log("   3. 或者使用PC脚本自动获取Token")
        
        # 模拟等待（实际应该读取数据包）
        while self.running:
            time.sleep(1)
            # 这里应该实现真正的数据包拦截逻辑
            # 但由于复杂性，暂时跳过
    
    def _capture_packets(self):
        """捕获数据包（主循环）"""
        if not self.vpn_interface:
            self.log("❌ VPN接口未建立")
            return
        
        self.log("📦 开始捕获数据包...")
        
        try:
            # 获取文件描述符
            FileInputStream = autoclass('java.io.FileInputStream')
            FileOutputStream = autoclass('java.io.FileOutputStream')
            
            in_stream = FileInputStream(self.vpn_interface.getFileDescriptor())
            out_stream = FileOutputStream(self.vpn_interface.getFileDescriptor())
            
            buffer_size = 32767
            packet_buffer = bytearray(buffer_size)
            
            while self.running:
                try:
                    # 读取数据包
                    length = in_stream.read(packet_buffer)
                    
                    if length > 0:
                        # 解析IP包
                        packet_data = bytes(packet_buffer[:length])
                        self._parse_packet(packet_data)
                        
                        # 将数据包转发出去（保持网络连通）
                        out_stream.write(packet_buffer, 0, length)
                        
                except Exception as e:
                    if self.running:
                        self.log(f"⚠️ 数据包处理错误: {e}")
                    continue
                    
        except Exception as e:
            self.log(f"❌ 抓包循环错误: {e}")
            import traceback
            self.log(traceback.format_exc())
        finally:
            self.log("📦 数据包捕获已停止")
    
    def _parse_packet(self, packet_data):
        """解析IP数据包"""
        try:
            # 检查IP版本
            if len(packet_data) < 20:
                return
            
            version = (packet_data[0] >> 4) & 0xF
            if version != 4:  # 只处理IPv4
                return
            
            # 获取IP头长度
            ihl = (packet_data[0] & 0xF) * 4
            
            # 获取协议类型
            protocol = packet_data[9]
            
            # 只处理TCP (6)
            if protocol != 6:
                return
            
            # TCP数据从IP头之后开始
            if len(packet_data) < ihl + 20:
                return
            
            tcp_data = packet_data[ihl:]
            
            # 获取TCP数据偏移
            tcp_header_len = ((tcp_data[12] >> 4) & 0xF) * 4
            
            # TCP payload
            if len(tcp_data) > tcp_header_len:
                payload = tcp_data[tcp_header_len:]
                
                # 尝试解析为HTTP
                self._parse_http(payload)
                
        except Exception as e:
            # 静默处理解析错误
            pass
    
    def _parse_http(self, data):
        """解析HTTP数据"""
        try:
            # 转换为字符串
            text = data.decode('utf-8', errors='ignore')
            
            # 检查是否包含目标域名
            if self.target_host not in text:
                return
            
            # 检查是否是HTTP请求
            if not (text.startswith('GET ') or 
                   text.startswith('POST ') or
                   text.startswith('PUT ') or
                   text.startswith('DELETE ')):
                return
            
            self.log(f"🔍 检测到目标域名流量: {self.target_host}")
            
            # 提取Token
            match = self.token_pattern.search(text)
            if match:
                token = match.group(1)
                self.log(f"🎯 捕获到Token: {token[:20]}...")
                
                # 提取其他headers
                headers = self._extract_headers(text)
                
                # 回调
                if self.token_callback:
                    self.token_callback(token, headers)
                    
        except Exception as e:
            pass
    
    def stop(self):
        """停止 VPN 服务"""
        self.running = False
        
        # 关闭VPN接口
        if ANDROID and hasattr(self, 'vpn_interface') and self.vpn_interface:
            try:
                # 关闭VPN接口
                self.vpn_interface.close()
                self.vpn_interface = None
            except Exception as e:
                self.log(f"⚠️ 关闭VPN接口时出错: {e}")
        
        self.log("⏹️ VPN抓包服务已停止")
    
    def _extract_headers(self, packet_str):
        """提取 HTTP Headers"""
        headers = {}
        
        patterns = {
            'club-id': r'club-id:\s*(\d+)',
            'role-id': r'role-id:\s*(\d+)',
            'tenant-id': r'tenant-id:\s*(\d+)',
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, packet_str, re.IGNORECASE)
            if match:
                headers[key] = match.group(1)
        
        return headers
    
    def log(self, message):
        """输出日志"""
        if self.log_callback:
            self.log_callback(message)


# ==================== 完整VPN实现（需要Java Service支持）====================
# 
# 注意：要实现完整的VPN功能，需要：
# 1. 创建一个Java VPN Service类
# 2. 在AndroidManifest.xml中注册Service
# 3. 通过JNI调用Java Service
# 
# 由于Python for Android的限制，完整的VPN实现比较复杂。
# 建议使用以下替代方案：
# 1. 使用Charles/Fiddler等抓包工具
# 2. 手动输入Token
# 3. 使用PC脚本自动获取Token
# 
# ============================================================================

if ANDROID:
    class VpnServiceHelper:
        """VPN Service 辅助类（用于未来扩展）"""
        
        @staticmethod
        def create_vpn_builder(context):
            """创建VPN Builder"""
            try:
                VpnService = autoclass('android.net.VpnService')
                Builder = autoclass('android.net.VpnService$Builder')
                
                # 注意：Builder需要在VpnService实例中创建
                # 这里提供一个占位实现
                return None
            except Exception as e:
                print(f"创建VPN Builder失败: {e}")
                return None
