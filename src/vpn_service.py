#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Token 捕获服务
通过本地 VPN 抓包自动提取 Authorization Token
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
    """VPN Token 捕获器"""
    
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
    
    def start_vpn(self):
        """启动 VPN 服务"""
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
                mActivity.startActivityForResult(intent, 0)
                
                # 等待用户授权 (简化处理，实际应该监听结果)
                time.sleep(2)
            else:
                self.log("✅ VPN权限已授予")
            
            # 启动VPN连接
            self._establish_vpn()
            
            # 启动数据包处理线程
            self.running = True
            threading.Thread(target=self._capture_packets, daemon=True).start()
            
            self.log("✅ VPN抓包服务已启动")
            return True
            
        except Exception as e:
            self.log(f"❌ VPN启动失败: {e}")
            import traceback
            self.log(traceback.format_exc())
            return False
    
    def _establish_vpn(self):
        """建立VPN连接"""
        try:
            VpnService = autoclass('android.net.VpnService')
            Builder = autoclass('android.net.VpnService$Builder')
            
            # 获取VpnService.Builder
            # 注意：这需要在VpnService子类中调用
            # 由于Python限制，我们使用简化的反射方式
            
            self.log("📡 正在建立VPN隧道...")
            
            # 创建Builder (需要在VpnService上下文中)
            builder = Builder(mActivity)
            
            # 配置VPN
            builder.addAddress("10.0.0.2", 32)  # VPN虚拟IP
            builder.addRoute("0.0.0.0", 0)      # 路由所有流量
            builder.addDnsServer("8.8.8.8")     # DNS服务器
            builder.setSession("GrabOrder VPN") # 会话名称
            
            # 建立VPN接口
            self.vpn_interface = builder.establish()
            
            if self.vpn_interface:
                self.log("✅ VPN隧道建立成功")
            else:
                self.log("❌ VPN隧道建立失败")
                
        except Exception as e:
            self.log(f"❌ 建立VPN失败: {e}")
            import traceback
            self.log(traceback.format_exc())
    
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
        
        if ANDROID and self.vpn_service:
            try:
                self.vpn_service.stopSelf()
            except:
                pass
        
        self.log("⏹️ VPN抓包服务已停止")
    
    def _process_packets(self):
        """处理数据包"""
        while self.running:
            try:
                # 从队列获取数据包
                packet = self.packet_queue.get(timeout=1)
                
                # 解析 HTTP 请求
                self._parse_http_packet(packet)
                
            except:
                continue
    
    def _parse_http_packet(self, packet_data):
        """解析 HTTP 数据包"""
        try:
            # 转换为字符串
            packet_str = packet_data.decode('utf-8', errors='ignore')
            
            # 检查是否是目标域名
            if self.target_host not in packet_str:
                return
            
            # 提取 Token
            match = self.token_pattern.search(packet_str)
            if not match:
                return
            
            token = match.group(1)
            
            # 提取其他 headers
            headers = self._extract_headers(packet_str)
            
            self.log(f"🎯 捕获到Token: {token[:20]}...")
            
            # 回调
            if self.token_callback:
                self.token_callback(token, headers)
        
        except Exception as e:
            pass  # 忽略解析错误
    
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


# ==================== Android VPN Service ====================

if ANDROID:
    class VpnService(PythonJavaClass):
        """Android VPN Service"""
        __javainterfaces__ = ['android/net/VpnService']
        __javacontext__ = 'app'
        
        def __init__(self):
            super().__init__()
            self.capture_instance = None
        
        @java_method('()V')
        def onCreate(self):
            """Service 创建"""
            pass
        
        @java_method('(Landroid/content/Intent;I)I')
        def onStartCommand(self, intent, flags, startId):
            """Service 启动"""
            self._establish_vpn()
            return 1  # START_STICKY
        
        @java_method('()V')
        def onDestroy(self):
            """Service 销毁"""
            pass
        
        def _establish_vpn(self):
            """建立 VPN 连接"""
            try:
                Builder = autoclass('android.net.VpnService$Builder')
                ParcelFileDescriptor = autoclass('android.os.ParcelFileDescriptor')
                
                builder = Builder(self)
                builder.setSession("GrabOrderVPN")
                builder.addAddress("10.0.0.2", 32)
                builder.addRoute("0.0.0.0", 0)
                
                # 建立连接
                vpn_interface = builder.establish()
                
                if vpn_interface:
                    # 启动数据包转发线程
                    threading.Thread(
                        target=self._forward_packets,
                        args=(vpn_interface,),
                        daemon=True
                    ).start()
            
            except Exception as e:
                print(f"VPN建立失败: {e}")
        
        def _forward_packets(self, vpn_interface):
            """转发数据包"""
            import socket
            
            FileInputStream = autoclass('java.io.FileInputStream')
            FileOutputStream = autoclass('java.io.FileOutputStream')
            
            # 输入输出流
            in_fd = vpn_interface.getFileDescriptor()
            input_stream = FileInputStream(in_fd)
            output_stream = FileOutputStream(in_fd)
            
            buffer_size = 32767
            packet = bytearray(buffer_size)
            
            while True:
                try:
                    # 读取数据包
                    length = input_stream.read(packet, 0, buffer_size)
                    
                    if length > 0:
                        packet_data = bytes(packet[:length])
                        
                        # 发送到解析队列
                        if self.capture_instance:
                            self.capture_instance.packet_queue.put(packet_data)
                        
                        # 转发数据包（保持网络正常）
                        output_stream.write(packet_data)
                
                except Exception as e:
                    break

