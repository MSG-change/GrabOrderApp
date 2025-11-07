#!/usr/bin/env python3
"""
本地 W 参数生成器
基于 jiyanv4 的代码
"""

import hashlib
import random
import string
import execjs
import os


class LocalWGenerator:
    """本地 W 参数生成器"""
    
    def __init__(self, js_file_path: str = None):
        """
        初始化 W 参数生成器
        
        Args:
            js_file_path: gcaptcha4_click.js 文件路径，默认在 jiyanv4 目录
        """
        if js_file_path is None:
            # 默认路径：当前目录下的 jiyanv4/gcaptcha4_click.js
            current_dir = os.path.dirname(os.path.abspath(__file__))
            js_file_path = os.path.join(current_dir, "jiyanv4", "gcaptcha4_click.js")
        
        if not os.path.exists(js_file_path):
            raise FileNotFoundError(f"找不到 JS 文件: {js_file_path}")
        
        # 设置工作目录为 JS 文件所在目录，以便 require 能找到 node_modules
        self.js_dir = os.path.dirname(js_file_path)
        original_dir = os.getcwd()
        
        try:
            print(f"🔧 加载 JS 文件: {js_file_path}")
            
            # 切换到 JS 文件所在目录
            os.chdir(self.js_dir)
            
            with open(js_file_path, "r", encoding="utf-8") as f:
                js_code = f.read()
                # 使用 Node.js 运行时（支持 require）
                self.ctll = execjs.compile(js_code)
            
            print("✅ JS 文件加载成功")
        
        finally:
            # 恢复原始工作目录
            os.chdir(original_dir)
    
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
        """
        PoW 计算
        
        Args:
            lot_number: 批次号
            captcha_id: 验证码ID
            hashfunc: 哈希函数 (md5/sha1/sha256)
            version: 版本
            bits: 位数
            datetime: 时间戳
            r: 保留参数（通常为空）
        
        Returns:
            (pow_msg, pow_sign)
        """
        _ = bits % 4
        u = int(bits / 4)
        c = '0' * (u + 1)  # 创建一个由 '0' 组成的字符串，长度为 u + 1
        h = f"{version}|{bits}|{hashfunc}|{datetime}|{captcha_id}|{lot_number}|{r}|"
        
        while True:
            l = self.guid()  # 随机生成一个 GUID
            p = h + l  # 将 GUID 和其他参数拼接成字符串
            f = self.hash_function(p, hashfunc)  # 使用指定的哈希算法进行哈希计算
            
            if f is None:
                raise ValueError("Invalid hash function")
            
            if _ == 0:
                if f.startswith(c):  # 如果哈希值以指定数量的 '0' 开头
                    return h + l, f
            elif f.startswith(c):
                g = int(f[u], 16)  # 提取哈希值中第 u 个字符
                d = {1: 7, 2: 3, 3: 1}.get(_, None)
                
                if d is not None and g <= d:  # 如果满足条件
                    return h + l, f
    
    @staticmethod
    def num_to_coordinate(pic_index):
        """
        将图片索引转换为坐标
        
        Args:
            pic_index: 图片索引，如 "0,3,8" 或 [0, 3, 8]
        
        Returns:
            坐标列表，如 [[1,1], [2,1], [3,3]]
        """
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
            pic_index: 图片索引，如 "0,3,8" 或 [0, 3, 8]
        
        Returns:
            W 参数字符串
        """
        # 1. 计算 PoW
        pow_msg, pow_sign = self.pow_calculate(
            lot_number, captcha_id, hashfunc, version, bits, datetime, ""
        )
        
        # 2. 转换坐标
        userresponse = self.num_to_coordinate(pic_index)
        
        # 3. 调用 JS 生成 W（需要在 JS 文件所在目录执行）
        original_dir = os.getcwd()
        try:
            os.chdir(self.js_dir)
            w = self.ctll.call("get_click_w", lot_number, pow_msg, pow_sign, userresponse)
        finally:
            os.chdir(original_dir)
        
        return w


# 测试代码
if __name__ == "__main__":
    print("=" * 70)
    print("🧪 测试本地 W 参数生成器")
    print("=" * 70)
    print()
    
    try:
        # 初始化生成器
        generator = LocalWGenerator()
        print()
        
        # 测试数据（从你之前的请求中获取）
        test_data = {
            "lot_number": "eb6e3c4b6c8f44a7a75a062a25455ebe",
            "captcha_id": "045e2c229998a88721e32a763bc0f7b8",
            "version": "1",
            "bits": 0,
            "datetime": "2025-11-07T15:47:10.906472+08:00",
            "hashfunc": "md5",
            "pic_index": "0,3,8"  # 测试数据
        }
        
        print("📝 测试参数:")
        print(f"   lot_number: {test_data['lot_number']}")
        print(f"   captcha_id: {test_data['captcha_id']}")
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

