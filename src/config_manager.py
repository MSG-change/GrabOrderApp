#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置管理器
"""

import json
import os


class ConfigManager:
    """配置管理"""
    
    def __init__(self, config_file='config.json'):
        """初始化"""
        # 配置文件路径
        try:
            # Android 内部存储
            from android.storage import app_storage_path
            self.config_dir = app_storage_path()
        except:
            # PC 开发环境
            self.config_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        self.config_path = os.path.join(self.config_dir, config_file)
        
        # 默认配置
        self.default_config = {
            'phone': '18113011654',
            'api_base_url': 'https://dysh.dyswl.com',
            'category_id': '131',  # 考核单分类ID
            'check_interval': 2,
            'token': '',
            'club_id': '',
            'role_id': '',
            'tenant_id': '',
        }
        
        # 加载配置
        self.config = self.load_config()
    
    def load_config(self):
        """加载配置"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 合并默认配置
                for key, value in self.default_config.items():
                    if key not in config:
                        config[key] = value
                
                return config
            except:
                pass
        
        return self.default_config.copy()
    
    def save_config(self):
        """保存配置"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"保存配置失败: {e}")
            return False
    
    def get_config(self):
        """获取配置"""
        return self.config
    
    def update_config(self, key, value):
        """更新配置"""
        self.config[key] = value
        self.save_config()
    
    def update_token(self, token, headers=None):
        """更新 Token"""
        self.config['token'] = token
        
        if headers:
            if 'club-id' in headers:
                self.config['club_id'] = headers['club-id']
            if 'role-id' in headers:
                self.config['role_id'] = headers['role-id']
            if 'tenant-id' in headers:
                self.config['tenant_id'] = headers['tenant-id']
        
        self.save_config()
    
    def get_headers(self):
        """获取请求头"""
        headers = {
            'Content-Type': 'application/json',
            'user-agent': 'Mozilla/5.0 (Linux; Android 12; 23127PN0CC Build/W528JS; wv) AppleWebKit/537.36',
            'Host': 'dysh.dyswl.com',
        }
        
        if self.config.get('token'):
            headers['authorization'] = f"Bearer {self.config['token']}"
        
        if self.config.get('club_id'):
            headers['club-id'] = self.config['club_id']
        
        if self.config.get('role_id'):
            headers['role-id'] = self.config['role_id']
        
        if self.config.get('tenant_id'):
            headers['tenant-id'] = self.config['tenant_id']
        
        return headers

