#!/usr/bin/env python3
"""
Geetest 验证码助手 - 远程AI版本
使用远程AI服务器，避免本地依赖问题
"""

import requests
import json
import time
import uuid
from typing import Optional, Dict

class GeetestHelperRemote:
    """使用远程AI服务器的Geetest助手"""
    
    def __init__(self, ai_server_url=None, captcha_id=None):
        """
        初始化
        
        Args:
            ai_server_url: AI服务器地址，默认从环境变量读取
            captcha_id: Geetest captcha ID
        """
        import os
        self.ai_server_url = ai_server_url or os.environ.get('AI_SERVER_URL', 'http://154.219.127.13:8889')
        self.captcha_id = captcha_id or "045e2c229998a88721e32a763bc0f7b8"
        
        print(f"[GeetestRemote] Initialized")
        print(f"  AI Server: {self.ai_server_url}")
        print(f"  Captcha ID: {self.captcha_id}")
    
    def verify(self, challenge=None):
        """
        调用远程AI服务进行验证
        
        Args:
            challenge: 挑战值（可选）
            
        Returns:
            dict: 验证结果
                {
                    'success': True/False,
                    'lot_number': '...',
                    'captcha_output': '...',
                    'pass_token': '...',
                    'gen_time': '...',
                    'error': '...' (如果失败)
                }
        """
        if not challenge:
            challenge = str(uuid.uuid4())
        
        try:
            # 调用远程AI API
            response = requests.post(
                f"{self.ai_server_url}/api/verify",
                json={
                    'captcha_id': self.captcha_id,
                    'challenge': challenge,
                    'threshold': 0.7
                },
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('success'):
                    # 检查W参数长度
                    captcha_output = result.get('captcha_output', '')
                    if len(captcha_output) < 100 or len(captcha_output) > 500:
                        print(f"[WARNING] W parameter length abnormal: {len(captcha_output)}")
                    
                    return {
                        'success': True,
                        'lot_number': result.get('lot_number'),
                        'captcha_output': captcha_output,
                        'pass_token': result.get('pass_token'),
                        'gen_time': result.get('gen_time'),
                        'answers': result.get('answers', [])
                    }
                else:
                    return {
                        'success': False,
                        'error': result.get('error', 'Unknown error')
                    }
            else:
                return {
                    'success': False,
                    'error': f'HTTP {response.status_code}'
                }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def generate_challenge(self, order_id):
        """生成challenge值"""
        return str(uuid.uuid4())
