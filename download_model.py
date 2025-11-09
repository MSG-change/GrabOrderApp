#!/usr/bin/env python3
"""
下载模型文件脚本
由于模型文件太大(137MB)，无法提交到GitHub
使用此脚本从云端下载
"""

import os
import requests
from tqdm import tqdm

def download_model():
    """下载模型文件"""
    
    # 模型文件URL（需要替换为实际的下载地址）
    # 可以使用：
    # 1. Google Drive
    # 2. 百度网盘
    # 3. 阿里云OSS
    # 4. GitHub Releases
    # 5. 自建服务器
    
    MODEL_URL = "https://your-server.com/best_siamese_model.pth"  # 替换为实际地址
    MODEL_PATH = "best_siamese_model.pth"
    MODEL_SIZE = 144114997  # 137.44 MB
    
    if os.path.exists(MODEL_PATH):
        print(f"✅ 模型文件已存在: {MODEL_PATH}")
        file_size = os.path.getsize(MODEL_PATH)
        if file_size == MODEL_SIZE:
            print(f"   文件大小正确: {file_size/1024/1024:.2f} MB")
            return True
        else:
            print(f"⚠️  文件大小不匹配: {file_size} != {MODEL_SIZE}")
            print(f"   重新下载...")
    
    print(f"📥 下载模型文件...")
    print(f"   URL: {MODEL_URL}")
    print(f"   大小: {MODEL_SIZE/1024/1024:.2f} MB")
    
    try:
        response = requests.get(MODEL_URL, stream=True)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        
        with open(MODEL_PATH, 'wb') as f:
            with tqdm(total=total_size, unit='B', unit_scale=True, desc="下载进度") as pbar:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        pbar.update(len(chunk))
        
        print(f"✅ 下载完成: {MODEL_PATH}")
        return True
        
    except Exception as e:
        print(f"❌ 下载失败: {e}")
        return False


def check_model():
    """检查模型文件"""
    MODEL_PATH = "best_siamese_model.pth"
    
    if not os.path.exists(MODEL_PATH):
        print(f"❌ 模型文件不存在")
        print(f"   请运行: python download_model.py")
        return False
    
    file_size = os.path.getsize(MODEL_PATH)
    print(f"✅ 模型文件存在")
    print(f"   路径: {MODEL_PATH}")
    print(f"   大小: {file_size/1024/1024:.2f} MB")
    
    # 尝试加载模型验证
    try:
        import torch
        checkpoint = torch.load(MODEL_PATH, map_location='cpu')
        if 'model_state_dict' in checkpoint:
            print(f"   准确率: {checkpoint.get('val_acc', 0)*100:.2f}%")
        print(f"✅ 模型文件有效")
        return True
    except Exception as e:
        print(f"❌ 模型文件无效: {e}")
        return False


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'check':
        check_model()
    else:
        download_model()
