#!/usr/bin/env python3
"""
下载模型文件脚本
从GitHub Releases下载模型文件
"""

import os
import sys
import requests
import hashlib

def download_with_progress(url, filepath):
    """带进度条的下载"""
    try:
        # 尝试导入tqdm，如果没有就用简单进度
        from tqdm import tqdm
        use_tqdm = True
    except ImportError:
        use_tqdm = False
        print("提示: 安装tqdm可以显示进度条 (pip install tqdm)")
    
    response = requests.get(url, stream=True)
    response.raise_for_status()
    
    total_size = int(response.headers.get('content-length', 0))
    
    with open(filepath, 'wb') as f:
        if use_tqdm:
            with tqdm(total=total_size, unit='B', unit_scale=True, desc="下载进度") as pbar:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        pbar.update(len(chunk))
        else:
            downloaded = 0
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        print(f"\r下载进度: {percent:.1f}% ({downloaded}/{total_size} bytes)", end='')
            print()  # 换行

def download_model():
    """下载模型文件"""
    
    # GitHub Release配置
    GITHUB_OWNER = "MSG-change"
    GITHUB_REPO = "GrabOrderApp"
    VERSION = "v1.7.2"
    MODEL_FILENAME = "best_siamese_model.pth"
    
    # 构建下载URL
    MODEL_URL = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/download/{VERSION}/{MODEL_FILENAME}"
    
    # 备用镜像地址（使用GitHub代理加速）
    MIRROR_URLS = [
        MODEL_URL,  # 原始地址
        f"https://ghproxy.com/{MODEL_URL}",  # ghproxy镜像
        f"https://mirror.ghproxy.com/{MODEL_URL}",  # 备用镜像
        MODEL_URL.replace("github.com", "download.fastgit.org"),  # FastGit镜像
    ]
    
    MODEL_PATH = "best_siamese_model.pth"
    MODEL_SIZE = 144114997  # 137.44 MB
    MODEL_MD5 = "YOUR_MD5_HASH"  # 需要计算实际的MD5
    
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
    print(f"   版本: {VERSION}")
    print(f"   大小: {MODEL_SIZE/1024/1024:.2f} MB")
    print()
    
    # 尝试从多个镜像下载
    for i, url in enumerate(MIRROR_URLS, 1):
        print(f"尝试源 {i}/{len(MIRROR_URLS)}: {url[:50]}...")
        
        try:
            # 先测试连接
            test_response = requests.head(url, timeout=5, allow_redirects=True)
            if test_response.status_code == 404:
                print(f"   ❌ 文件不存在 (404)")
                continue
                
            # 开始下载
            download_with_progress(url, MODEL_PATH)
            
            # 验证文件大小
            file_size = os.path.getsize(MODEL_PATH)
            if file_size == MODEL_SIZE:
                print(f"✅ 下载完成: {MODEL_PATH}")
                print(f"   文件大小: {file_size/1024/1024:.2f} MB")
                return True
            else:
                print(f"⚠️  文件大小不匹配: {file_size} != {MODEL_SIZE}")
                os.remove(MODEL_PATH)
                continue
                
        except requests.exceptions.Timeout:
            print(f"   ⏱️ 连接超时，尝试下一个源...")
            continue
        except requests.exceptions.ConnectionError:
            print(f"   ❌ 连接失败，尝试下一个源...")
            continue
        except Exception as e:
            print(f"   ❌ 下载失败: {e}")
            if os.path.exists(MODEL_PATH):
                os.remove(MODEL_PATH)
            continue
    
    print(f"❌ 所有下载源都失败了")
    print(f"")
    print(f"🔧 手动下载方法：")
    print(f"1. 访问: https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/tag/{VERSION}")
    print(f"2. 下载: {MODEL_FILENAME}")
    print(f"3. 放置到: {os.path.abspath(MODEL_PATH)}")
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
