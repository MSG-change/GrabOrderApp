#!/usr/bin/env python3
"""
Android WebView W 参数生成器
在 Android WebView 中执行 JS 代码，无需 Node.js
"""

import os
import json
import time
import hashlib
import random
import string

try:
    from jnius import autoclass, cast
    ANDROID_AVAILABLE = True
except ImportError:
    ANDROID_AVAILABLE = False


class AndroidWebViewWGenerator:
    """使用 Android WebView 执行 JS 生成 W 参数"""
    
    def __init__(self, js_file_path: str = None):
        """
        初始化
        
        Args:
            js_file_path: gcaptcha4_click.js 文件路径
        """
        if not ANDROID_AVAILABLE:
            raise RuntimeError("此类只能在 Android 上使用")
        
        # 默认路径
        if js_file_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(current_dir)
            js_file_path = os.path.join(parent_dir, "assets", "jiyanv4", "gcaptcha4_click.js")
        
        if not os.path.exists(js_file_path):
            raise FileNotFoundError(f"找不到 JS 文件: {js_file_path}")
        
        print(f"🔧 初始化 WebView W 参数生成器...")
        print(f"   JS文件: {js_file_path}")
        
        # 读取 JS 代码
        with open(js_file_path, 'r', encoding='utf-8') as f:
            self.js_code = f.read()
        
        # 初始化 WebView
        self._init_webview()
        
        print("✅ WebView 初始化完成")
    
    def _init_webview(self):
        """初始化 WebView"""
        # 获取当前活动
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        activity = PythonActivity.mActivity
        
        # 创建 WebView
        WebView = autoclass('android.webkit.WebView')
        WebSettings = autoclass('android.webkit.WebSettings')
        
        # 必须在主线程创建 WebView
        def create_webview():
            self.webview = WebView(activity)
            settings = self.webview.getSettings()
            settings.setJavaScriptEnabled(True)
            settings.setDomStorageEnabled(True)
            
            # 加载空白页
            self.webview.loadUrl("about:blank")
            
            # 注入 JS 代码
            self._inject_js()
        
        # 在主线程执行
        activity.runOnUiThread(create_webview)
        
        # 等待初始化完成
        time.sleep(0.5)
    
    def _inject_js(self):
        """注入 JS 代码到 WebView"""
        # 包装 JS 代码
        wrapped_js = f"""
        (function() {{
            {self.js_code}
            
            // 暴露生成函数
            window.generateW = function(lot_number, pow_msg, pow_sign, userresponse) {{
                try {{
                    var result = get_click_w(lot_number, pow_msg, pow_sign, userresponse);
                    return result;
                }} catch(e) {{
                    return "ERROR: " + e.toString();
                }}
            }};
        }})();
        """
        
        # 执行 JS
        self.webview.evaluateJavascript(wrapped_js, None)
    
    @staticmethod
    def guid():
        """生成一个随机 GUID 字符串"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    
    @staticmethod
    def hash_function(s, algo):
        """根据指定的算法进行哈希计算"""
        if algo == "md5":
            return hashlib.md5(s.encode()).hexdigest()
        elif algo == "sha1":
            return hashlib.sha1(s.encode()).hexdigest()
        elif algo == "sha256":
            return hashlib.sha256(s.encode()).hexdigest()
        return None
    
    def pow_calculate(self, lot_number, captcha_id, hashfunc, version, bits, datetime, r=""):
        """PoW 计算（纯 Python 实现）"""
        _ = bits % 4
        u = int(bits / 4)
        c = '0' * (u + 1)
        h = f"{version}|{bits}|{hashfunc}|{datetime}|{captcha_id}|{lot_number}|{r}|"
        
        while True:
            l = self.guid()
            p = h + l
            f = self.hash_function(p, hashfunc)
            
            if f is None:
                raise ValueError("Invalid hash function")
            
            if _ == 0:
                if f.startswith(c):
                    return h + l, f
            elif f.startswith(c):
                g = int(f[u], 16)
                d = {1: 7, 2: 3, 3: 1}.get(_, None)
                
                if d is not None and g <= d:
                    return h + l, f
    
    @staticmethod
    def num_to_coordinate(pic_index):
        """将图片索引转换为坐标"""
        if isinstance(pic_index, str):
            num_list = pic_index.strip().split(",")
            num_list = [int(num) + 1 for num in num_list]
        elif isinstance(pic_index, list):
            num_list = [int(num) + 1 for num in pic_index]
        else:
            raise ValueError(f"pic_index 类型错误: {type(pic_index)}")
        
        return [[(int(num) - 1) // 3 + 1, (int(num) - 1) % 3 + 1] for num in num_list]
    
    def _execute_js(self, js_code):
        """
        在 WebView 中执行 JS 并获取结果
        
        Args:
            js_code: 要执行的 JS 代码
        
        Returns:
            执行结果
        """
        # 结果存储
        result_holder = {'value': None, 'done': False}
        
        # 回调类
        ValueCallback = autoclass('android.webkit.ValueCallback')
        
        class ResultCallback(PythonJavaClass):
            __javainterfaces__ = ['android/webkit/ValueCallback']
            
            def __init__(self, holder):
                super().__init__()
                self.holder = holder
            
            @java_method('(Ljava/lang/Object;)V')
            def onReceiveValue(self, value):
                self.holder['value'] = value
                self.holder['done'] = True
        
        # 创建回调
        callback = ResultCallback(result_holder)
        
        # 执行 JS
        self.webview.evaluateJavascript(js_code, callback)
        
        # 等待结果（最多 5 秒）
        timeout = 5
        start_time = time.time()
        while not result_holder['done'] and (time.time() - start_time) < timeout:
            time.sleep(0.01)
        
        if not result_holder['done']:
            raise TimeoutError("JS 执行超时")
        
        return result_holder['value']
    
    def generate_w(self, lot_number, captcha_id, version, bits, datetime, hashfunc, pic_index):
        """
        生成 W 参数
        
        Args:
            lot_number: 批次号
            captcha_id: 验证码ID
            version: 版本
            bits: 位数
            datetime: 时间戳
            hashfunc: 哈希函数
            pic_index: 图片索引
        
        Returns:
            W 参数字符串
        """
        # 1. Python 计算 PoW
        pow_msg, pow_sign = self.pow_calculate(
            lot_number, captcha_id, hashfunc, version, bits, datetime, ""
        )
        
        # 2. 转换坐标
        userresponse = self.num_to_coordinate(pic_index)
        
        # 3. 调用 WebView 中的 JS 生成 W
        js_call = f"""
        (function() {{
            var lot = {json.dumps(lot_number)};
            var pow_msg = {json.dumps(pow_msg)};
            var pow_sign = {json.dumps(pow_sign)};
            var userresponse = {json.dumps(userresponse)};
            
            return window.generateW(lot, pow_msg, pow_sign, userresponse);
        }})();
        """
        
        w_param = self._execute_js(js_call)
        
        # 处理结果
        if w_param and not w_param.startswith("ERROR:"):
            # 去除引号
            w_param = w_param.strip('"')
            return w_param
        else:
            raise RuntimeError(f"JS 执行失败: {w_param}")


# 为了兼容性
LocalWGenerator = AndroidWebViewWGenerator

