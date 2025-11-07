#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PC 端测试脚本
用于在不构建 APK 的情况下测试抢单逻辑
"""

import sys
import os
import time

# 添加路径
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'libs'))

from src.grab_service import GrabOrderService
from src.config_manager import ConfigManager


def test_grab_service():
    """测试抢单服务"""
    
    print("="*70)
    print("🧪 抢单服务测试 - PC 模式")
    print("="*70)
    print()
    
    # 加载配置
    config_mgr = ConfigManager()
    config = config_mgr.get_config()
    
    print("📋 当前配置:")
    print(f"  手机号: {config['phone']}")
    print(f"  API地址: {config['api_base_url']}")
    print(f"  产品分类: {config['category_id']}")
    print(f"  检查间隔: {config['check_interval']}秒")
    print()
    
    # 检查 Token
    if not config.get('token'):
        print("❌ 未配置 Token")
        print()
        print("请先配置 Token:")
        print(f"  编辑文件: {config_mgr.config_path}")
        print(f"  设置 token 字段")
        print()
        return
    
    print(f"✅ Token: {config['token'][:20]}...")
    print()
    
    # 创建抢单服务
    def log_callback(msg):
        print(f"  {msg}")
    
    service = GrabOrderService(
        phone=config['phone'],
        api_base_url=config['api_base_url'],
        log_callback=log_callback
    )
    
    # 设置 Token
    service.update_token(
        config['token'],
        {
            'club-id': config.get('club_id', ''),
            'role-id': config.get('role_id', ''),
            'tenant-id': config.get('tenant_id', ''),
        }
    )
    
    print("="*70)
    print("🚀 启动抢单服务...")
    print("="*70)
    print()
    
    # 启动服务
    service.start()
    
    # 运行测试
    try:
        print("⏱️  运行中... (按 Ctrl+C 停止)")
        print()
        
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print()
        print("="*70)
        print("⏹️  停止服务...")
        print("="*70)
        
        service.stop()
        
        print()
        print("✅ 测试完成")
        print()


if __name__ == '__main__':
    test_grab_service()

