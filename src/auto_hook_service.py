#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动 Hook 服务 - 纯手机端
自动连接 Frida 并 Hook 目标应用
"""

import os
import sys
import time
import threading

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


class AutoHookService:
    """自动 Hook 服务"""
    
    def __init__(self, target_package, log_callback=None):
        """
        初始化
        
        Args:
            target_package: 目标应用包名
            log_callback: 日志回调函数
        """
        self.target_package = target_package
        self.log_callback = log_callback
        
        self.device = None
        self.session = None
        self.script = None
        
        self.running = False
        self.hooked = False
        
        # Token 更新回调
        self.token_callback = None
        
        # Hook 脚本路径
        self.hook_script_path = None
    
    def set_token_callback(self, callback):
        """设置 Token 更新回调"""
        self.token_callback = callback
    
    def start(self):
        """启动 Hook 服务"""
        if not FRIDA_AVAILABLE:
            self.log("❌ Frida 库不可用")
            return False
        
        if self.running:
            self.log("⚠️ Hook 服务已在运行")
            return False
        
        self.running = True
        
        # 在后台线程连接
        thread = threading.Thread(target=self._connect_and_hook, daemon=True)
        thread.start()
        
        return True
    
    def stop(self):
        """停止 Hook 服务"""
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
        
        self.hooked = False
        self.log("⏹️ Hook 服务已停止")
    
    def _connect_and_hook(self):
        """连接并 Hook（后台线程）"""
        try:
            self.log("🔧 连接 Frida...")
            
            # 连接本地设备
            self.device = frida.get_local_device()
            self.log(f"✅ 已连接: {self.device}")
            
            # 等待目标应用启动
            self.log(f"📱 等待目标应用: {self.target_package}")
            
            max_retries = 30  # 最多等待 30 秒
            for i in range(max_retries):
                if not self.running:
                    return
                
                try:
                    # 尝试附加
                    self.session = self.device.attach(self.target_package)
                    self.log("✅ 已附加到目标应用")
                    break
                    
                except frida.ProcessNotFoundError:
                    if i == 0:
                        self.log("   请在目标应用中进行操作...")
                    time.sleep(1)
                    continue
            else:
                self.log("❌ 目标应用未运行或附加超时")
                self.running = False
                return
            
            # 加载 Hook 脚本
            script_code = self._load_hook_script()
            if not script_code:
                self.log("❌ Hook 脚本加载失败")
                self.running = False
                return
            
            self.log("🔧 加载 Hook 脚本...")
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_message)
            self.script.load()
            
            self.hooked = True
            self.log("✅ Hook 已激活")
            self.log("   等待目标应用发送网络请求...")
            
            # 保持运行
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            self.log(f"❌ Hook 失败: {e}")
            import traceback
            self.log(traceback.format_exc()[:200])
            self.running = False
            self.hooked = False
    
    def _load_hook_script(self):
        """加载 Hook 脚本"""
        try:
            # 尝试多个可能的路径
            possible_paths = []
            
            # Android 环境
            try:
                from jnius import autoclass
                PythonActivity = autoclass('org.kivy.android.PythonActivity')
                activity = PythonActivity.mActivity
                files_dir = activity.getFilesDir().getAbsolutePath()
                
                possible_paths.extend([
                    os.path.join(files_dir, 'frida_token_grabber.js'),
                    os.path.join(files_dir, 'assets', 'frida_token_grabber.js'),
                ])
            except:
                pass
            
            # 通用路径
            possible_paths.extend([
                'frida_token_grabber.js',
                './frida_token_grabber.js',
                '../frida_token_grabber.js',
                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frida_token_grabber.js'),
            ])
            
            # 查找脚本
            for path in possible_paths:
                if os.path.exists(path):
                    self.log(f"✅ 找到 Hook 脚本: {path}")
                    with open(path, 'r', encoding='utf-8') as f:
                        return f.read()
            
            self.log("⚠️ 未找到 Hook 脚本，使用内置脚本")
            return self._get_builtin_hook_script()
            
        except Exception as e:
            self.log(f"❌ 加载 Hook 脚本失败: {e}")
            return None
    
    def _get_builtin_hook_script(self):
        """获取内置 Hook 脚本"""
        return """
console.log("[*] Frida Hook 已加载");

const TARGET_HOST = "dysh.dyswl.com";

var tokenData = {
    token: "",
    clubId: "",
    roleId: "",
    tenantId: ""
};

function sendToken() {
    send({
        type: "token_update",
        data: {
            token: tokenData.token,
            club_id: tokenData.clubId,
            role_id: tokenData.roleId,
            tenant_id: tokenData.tenantId
        }
    });
}

Java.perform(function() {
    try {
        var RequestBuilder = Java.use("okhttp3.Request$Builder");
        
        RequestBuilder.build.implementation = function() {
            var request = this.build();
            
            try {
                var url = request.url().toString();
                
                if (url.indexOf(TARGET_HOST) !== -1) {
                    var headers = request.headers();
                    
                    var token = headers.get("authorization");
                    var clubId = headers.get("club-id");
                    var roleId = headers.get("role-id");
                    var tenantId = headers.get("tenant-id");
                    
                    var updated = false;
                    
                    if (token && token !== tokenData.token) {
                        tokenData.token = token.replace("Bearer ", "").trim();
                        updated = true;
                        console.log("[Token] " + tokenData.token.substring(0, 20) + "...");
                    }
                    
                    if (clubId && clubId !== tokenData.clubId) {
                        tokenData.clubId = clubId;
                        updated = true;
                    }
                    
                    if (roleId && roleId !== tokenData.roleId) {
                        tokenData.roleId = roleId;
                        updated = true;
                    }
                    
                    if (tenantId && tenantId !== tokenData.tenantId) {
                        tokenData.tenantId = tenantId;
                        updated = true;
                    }
                    
                    if (updated) {
                        sendToken();
                    }
                }
            } catch (e) {
                console.log("[!] Error: " + e);
            }
            
            return request;
        };
        
        console.log("[✓] OkHttp3 Hook 成功");
        
    } catch (e) {
        console.log("[!] Hook 失败: " + e);
    }
});
"""
    
    def _on_message(self, message, data):
        """处理 Frida 消息"""
        try:
            if message['type'] == 'send':
                payload = message['payload']
                
                if payload.get('type') == 'token_update':
                    token_data = payload.get('data', {})
                    
                    if self.token_callback:
                        self.token_callback(token_data)
                    
            elif message['type'] == 'error':
                self.log(f"⚠️ Hook 错误: {message.get('description', 'Unknown')}")
                
        except Exception as e:
            self.log(f"❌ 消息处理失败: {e}")
    
    def get_status(self):
        """获取状态"""
        return {
            'running': self.running,
            'hooked': self.hooked,
            'target': self.target_package
        }
    
    def log(self, message):
        """输出日志"""
        if self.log_callback:
            self.log_callback(message)
        else:
            print(message)

