#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Token 捕获服务
通过本地 VPN 抓包自动提取 Authorization Token
"""

import re
import threading
from queue import Queue

try:
    from jnius import autoclass, cast, PythonJavaClass, java_method
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
        self.vpn_service = None
        self.packet_queue = Queue()
        
        # 目标域名（抢单服务器）
        self.target_host = "dysh.dyswl.com"
        
        # Token 正则
        self.token_pattern = re.compile(r'authorization:\s*Bearer\s+([a-zA-Z0-9]+)')
    
    def start_vpn(self):
        """启动 VPN 服务"""
        if not ANDROID:
            self.log("⚠️ 非Android环境，VPN服务不可用")
            return
        
        try:
            # 启动 VPN Service
            Intent = autoclass('android.content.Intent')
            PythonActivity = autoclass('org.kivy.android.PythonActivity')
            
            intent = Intent(PythonActivity.mActivity, VpnService)
            PythonActivity.mActivity.startService(intent)
            
            # 启动数据包处理线程
            self.running = True
            threading.Thread(target=self._process_packets, daemon=True).start()
            
            self.log("✅ VPN抓包服务已启动")
            
        except Exception as e:
            self.log(f"❌ VPN启动失败: {e}")
    
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

