#!/usr/bin/env python3
"""
Android兼容的 W 参数生成器
使用远程API或pyjnius+WebView执行JS
"""

import requests
import hashlib
import random
import string


class AndroidWGenerator:
    """Android兼容的 W 参数生成器"""
    
    def __init__(self, api_url: str = "http://122.51.11.20:9088/captcha/w/"):
        """
        初始化 W 参数生成器
        
        Args:
            api_url: 第三方W参数生成API地址
        """
        self.api_url = api_url
        print(f"🔧 使用远程API生成W参数: {api_url}")
    
    @staticmethod
    def guid():
        """生成一个随机 GUID 字符串"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    
    def generate_w(self, 
                   lot_number: str,
                   captcha_id: str,
                   version: str,
                   bits: int,
                   datetime: str,
                   hashfunc: str,
                   pic_index: str) -> str:
        """
        生成 W 参数（使用远程API）
        
        Args:
            lot_number: 批次号
            captcha_id: 验证码ID
            version: 版本
            bits: 位数
            datetime: 时间戳
            hashfunc: 哈希函数 (md5/sha1/sha256)
            pic_index: 图片索引（逗号分隔，如 "0,3,8"）
        
        Returns:
            W 参数字符串
        """
        try:
            # 调用第三方API
            response = requests.post(
                self.api_url,
                json={
                    "lot_number": lot_number,
                    "captcha_id": captcha_id,
                    "version": version,
                    "bits": str(bits),
                    "datetime": datetime,
                    "hashfunc": hashfunc,
                    "pic_index": pic_index,
                    "client_type": "android"
                },
                timeout=10
            )
            
            response.raise_for_status()
            result = response.json()
            
            if result.get('code') == 200:
                w_param = result.get('data', {}).get('w')
                if w_param:
                    print(f"   ✅ W参数生成成功: {w_param[:50]}...")
                    return w_param
            
            print(f"   ⚠️  API返回异常: {result}")
            return None
        
        except Exception as e:
            print(f"   ❌ W参数生成失败: {e}")
            return None


# 为了兼容性，保持相同的类名
LocalWGenerator = AndroidWGenerator

