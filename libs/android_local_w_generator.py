#!/usr/bin/env python3
"""
Android 本地 W 参数生成器
使用 Android WebView 执行 JS，完全本地运行
"""

import os
import hashlib
import random
import string
import json
import time

try:
    from jnius import autoclass, PythonJavaClass, java_method
    from android.runnable import run_on_ui_thread
    ANDROID_AVAILABLE = True
except ImportError:
    ANDROID_AVAILABLE = False


class AndroidLocalWGenerator:
    """使用 Android WebView 本地执行 JS 生成 W 参数"""
    
    def __init__(self, js_file_path: str = None):
        """
        初始化
        
        Args:
            js_file_path: gcaptcha4_click.js 文件路径
        """
        if not ANDROID_AVAILABLE:
            raise RuntimeError("此生成器只能在 Android 上使用")
        
        # 默认路径
        if js_file_path is None:
            # 在 Android 上，assets 会被打包到应用目录
            import sys
            app_dir = os.path.dirname(sys.argv[0])
            js_file_path = os.path.join(app_dir, "assets", "jiyanv4", "gcaptcha4_click.js")
            
            # 备用路径
            if not os.path.exists(js_file_path):
                current_dir = os.path.dirname(os.path.abspath(__file__))
                parent_dir = os.path.dirname(current_dir)
                js_file_path = os.path.join(parent_dir, "assets", "jiyanv4", "gcaptcha4_click.js")
        
        if not os.path.exists(js_file_path):
            raise FileNotFoundError(f"找不到 JS 文件: {js_file_path}")
        
        print(f"🔧 初始化 Android 本地 W 参数生成器...")
        print(f"   JS文件: {js_file_path}")
        
        # 读取 JS 代码
        with open(js_file_path, 'r', encoding='utf-8') as f:
            self.js_code = f.read()
        
        # 初始化 WebView
        self.webview = None
        self.webview_ready = False
        self._init_webview()
        
        # 等待 WebView 初始化
        timeout = 5
        start = time.time()
        while not self.webview_ready and (time.time() - start) < timeout:
            time.sleep(0.1)
        
        if not self.webview_ready:
            raise RuntimeError("WebView 初始化超时")
        
        print("✅ Android 本地 W 参数生成器初始化完成")
    
    @run_on_ui_thread
    def _init_webview(self):
        """初始化 WebView（必须在主线程）"""
        try:
            # 获取当前活动
            PythonActivity = autoclass('org.kivy.android.PythonActivity')
            activity = PythonActivity.mActivity
            
            # 创建 WebView
            WebView = autoclass('android.webkit.WebView')
            WebSettings = autoclass('android.webkit.WebSettings')
            
            self.webview = WebView(activity)
            settings = self.webview.getSettings()
            settings.setJavaScriptEnabled(True)
            settings.setDomStorageEnabled(True)
            settings.setAllowFileAccess(True)
            settings.setAllowContentAccess(True)
            
            # 设置 WebViewClient（监听页面加载）
            WebViewClient = autoclass('android.webkit.WebViewClient')
            
            class MyWebViewClient(PythonJavaClass):
                __javainterfaces__ = ['android/webkit/WebViewClient']
                
                def __init__(self, generator):
                    super().__init__()
                    self.generator = generator
                
                @java_method('(Landroid/webkit/WebView;Ljava/lang/String;)V')
                def onPageFinished(self, view, url):
                    # 页面加载完成后注入 JS
                    self.generator._inject_js()
            
            self.webview.setWebViewClient(MyWebViewClient(self))
            
            # 加载空白页
            self.webview.loadUrl("about:blank")
            
            print("   ✅ WebView 创建成功")
        
        except Exception as e:
            print(f"   ❌ WebView 初始化失败: {e}")
            import traceback
            traceback.print_exc()
    
    @run_on_ui_thread
    def _inject_js(self):
        """注入 JS 代码到 WebView（必须在主线程）"""
        try:
            # 包装 JS 代码，暴露 generateW 函数
            wrapped_js = f"""
            (function() {{
                {self.js_code}
                
                // 暴露生成函数给 Java/Python 调用
                window.generateW = function(lot_number, pow_msg, pow_sign, userresponse) {{
                    try {{
                        var result = get_click_w(lot_number, pow_msg, pow_sign, userresponse);
                        return result;
                    }} catch(e) {{
                        return "ERROR: " + e.toString();
                    }}
                }};
                
                // 标记初始化完成
                window.w_generator_ready = true;
            }})();
            """
            
            # 注入 JS
            self.webview.evaluateJavascript(wrapped_js, None)
            
            # 标记就绪
            self.webview_ready = True
            
            print("   ✅ JS 代码注入成功")
        
        except Exception as e:
            print(f"   ❌ JS 注入失败: {e}")
            import traceback
            traceback.print_exc()
    
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
    
    def _execute_js_sync(self, js_code, timeout=5):
        """
        同步执行 JS 代码并获取结果
        
        Args:
            js_code: 要执行的 JS 代码
            timeout: 超时时间（秒）
        
        Returns:
            执行结果
        """
        # 结果容器
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
                if value:
                    self.holder['value'] = str(value)
                self.holder['done'] = True
        
        # 创建回调
        callback = ResultCallback(result_holder)
        
        # 在主线程执行 JS
        @run_on_ui_thread
        def execute():
            self.webview.evaluateJavascript(js_code, callback)
        
        execute()
        
        # 等待结果
        start_time = time.time()
        while not result_holder['done'] and (time.time() - start_time) < timeout:
            time.sleep(0.01)
        
        if not result_holder['done']:
            raise TimeoutError(f"JS 执行超时（{timeout}秒）")
        
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
        # 转义字符串，防止 JS 注入
        lot_escaped = lot_number.replace('"', '\\"').replace("'", "\\'")
        pow_msg_escaped = pow_msg.replace('"', '\\"').replace("'", "\\'")
        pow_sign_escaped = pow_sign.replace('"', '\\"').replace("'", "\\'")
        userresponse_json = json.dumps(userresponse)
        
        js_call = f'''
        (function() {{
            try {{
                return window.generateW(
                    "{lot_escaped}",
                    "{pow_msg_escaped}",
                    "{pow_sign_escaped}",
                    {userresponse_json}
                );
            }} catch(e) {{
                return "ERROR: " + e.toString();
            }}
        }})();
        '''
        
        # 执行 JS
        result = self._execute_js_sync(js_call)
        
        # 处理结果
        if result:
            # 去除 JSON 字符串的引号
            result = result.strip().strip('"\'')
            
            if result.startswith("ERROR:"):
                raise RuntimeError(f"JS 执行失败: {result}")
            
            return result
        else:
            raise RuntimeError("JS 执行返回空结果")


# 为了兼容性，提供别名
LocalWGenerator = AndroidLocalWGenerator


if __name__ == "__main__":
    print("=" * 70)
    print("🧪 测试 Android 本地 W 参数生成器")
    print("=" * 70)
    print()
    
    if not ANDROID_AVAILABLE:
        print("❌ 此模块只能在 Android 上运行")
        print("   请在 Android 设备上测试")
    else:
        print("✅ 在 Android 环境中")
        print("   初始化生成器...")
        
        try:
            generator = AndroidLocalWGenerator()
            
            # 测试数据
            test_data = {
                "lot_number": "eb6e3c4b6c8f44a7a75a062a25455ebe",
                "captcha_id": "045e2c229998a88721e32a763bc0f7b8",
                "version": "1",
                "bits": 0,
                "datetime": "2025-11-07T15:47:10.906472+08:00",
                "hashfunc": "md5",
                "pic_index": "0,3,8"
            }
            
            print()
            print("📝 测试参数:")
            print(f"   pic_index: {test_data['pic_index']}")
            print()
            
            print("🔄 生成 W 参数...")
            w = generator.generate_w(
                lot_number=test_data["lot_number"],
                captcha_id=test_data["captcha_id"],
                version=test_data["version"],
                bits=test_data["bits"],
                datetime=test_data["datetime"],
                hashfunc=test_data["hashfunc"],
                pic_index=test_data["pic_index"]
            )
            
            print()
            print("✅ W 参数生成成功!")
            print(f"   长度: {len(w)} 字符")
            print(f"   前100字符: {w[:100]}...")
            print()
            print("=" * 70)
        
        except Exception as e:
            print()
            print(f"❌ 测试失败: {e}")
            import traceback
            traceback.print_exc()

