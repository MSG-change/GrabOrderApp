#!/usr/bin/env python3
"""
QuickJS W 参数生成器
使用 QuickJS 在 Android 上执行 JS，无需 Node.js
"""

import os
import hashlib
import random
import string

try:
    from quickjs import Context
    QUICKJS_AVAILABLE = True
except ImportError:
    QUICKJS_AVAILABLE = False
    print("⚠️ python-quickjs 未安装，请运行: pip install python-quickjs")


class QuickJSWGenerator:
    """使用 QuickJS 执行 JS 生成 W 参数"""
    
    def __init__(self, js_file_path: str = None):
        """
        初始化
        
        Args:
            js_file_path: gcaptcha4_click.js 文件路径
        """
        if not QUICKJS_AVAILABLE:
            raise ImportError("python-quickjs 未安装，请运行: pip install python-quickjs")
        
        # 默认路径
        if js_file_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(current_dir)
            js_file_path = os.path.join(parent_dir, "assets", "jiyanv4", "gcaptcha4_click.js")
        
        if not os.path.exists(js_file_path):
            raise FileNotFoundError(f"找不到 JS 文件: {js_file_path}")
        
        print(f"🔧 初始化 QuickJS W 参数生成器...")
        print(f"   JS文件: {js_file_path}")
        
        # 读取 JS 代码
        with open(js_file_path, 'r', encoding='utf-8') as f:
            self.js_code = f.read()
        
        # 创建 QuickJS 上下文
        self.ctx = Context()
        
        # 执行 JS 代码（加载函数定义）
        try:
            self.ctx.eval(self.js_code)
            print("✅ JS 代码加载成功")
        except Exception as e:
            print(f"❌ JS 代码加载失败: {e}")
            raise
    
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
        
        # 3. 调用 QuickJS 中的 JS 函数生成 W
        js_call = f'''
            get_click_w(
                "{lot_number}",
                "{pow_msg}",
                "{pow_sign}",
                {str(userresponse).replace("'", '"')}
            )
        '''
        
        try:
            w_param = self.ctx.eval(js_call)
            return w_param
        except Exception as e:
            print(f"❌ JS 执行失败: {e}")
            raise


# 为了兼容性
LocalWGenerator = QuickJSWGenerator


# 测试代码
if __name__ == "__main__":
    print("=" * 70)
    print("🧪 测试 QuickJS W 参数生成器")
    print("=" * 70)
    print()
    
    try:
        # 初始化生成器
        generator = QuickJSWGenerator()
        print()
        
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
        
        print("📝 测试参数:")
        print(f"   lot_number: {test_data['lot_number']}")
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
        print()
        print("🎉 QuickJS 方案可用！")
        print("   可以集成到 Android APK 中")
        print("=" * 70)
    
    except ImportError as e:
        print()
        print(f"❌ 测试失败: {e}")
        print()
        print("请先安装 python-quickjs:")
        print("   pip install python-quickjs")
        print()
    
    except Exception as e:
        print()
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()

