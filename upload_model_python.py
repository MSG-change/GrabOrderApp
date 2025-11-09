#!/usr/bin/env python3
"""
使用Python上传模型文件到GitHub Releases
不需要GitHub CLI
"""

import os
import sys
import requests
from pathlib import Path

def create_release_and_upload(token=None):
    """创建Release并上传模型文件"""
    
    # 配置
    OWNER = "MSG-change"
    REPO = "GrabOrderApp"
    VERSION = "v1.7.2"
    MODEL_FILE = "best_siamese_model.pth"
    
    # GitHub Token（从环境变量或参数获取）
    if not token:
        token = os.environ.get('GITHUB_TOKEN')
    
    if not token:
        print("❌ 需要GitHub Token")
        print("获取方法：")
        print("1. 访问: https://github.com/settings/tokens")
        print("2. 点击 'Generate new token (classic)'")
        print("3. 选择权限: repo (完整权限)")
        print("4. 生成token并复制")
        print("")
        print("使用方法:")
        print("  export GITHUB_TOKEN=your_token_here")
        print("  python upload_model_python.py")
        print("或:")
        print("  python upload_model_python.py your_token_here")
        return False
    
    # 检查文件
    if not os.path.exists(MODEL_FILE):
        print(f"❌ 模型文件不存在: {MODEL_FILE}")
        return False
    
    file_size = os.path.getsize(MODEL_FILE)
    print(f"📦 准备上传模型到GitHub Release...")
    print(f"   仓库: {OWNER}/{REPO}")
    print(f"   版本: {VERSION}")
    print(f"   文件: {MODEL_FILE}")
    print(f"   大小: {file_size/1024/1024:.2f} MB")
    print()
    
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
    }
    
    try:
        # 步骤1: 检查Release是否存在
        print("检查Release是否存在...")
        get_url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/tags/{VERSION}"
        response = requests.get(get_url, headers=headers)
        
        if response.status_code == 200:
            release = response.json()
            release_id = release['id']
            upload_url = release['upload_url'].replace('{?name,label}', '')
            print(f"✅ Release已存在 (ID: {release_id})")
        else:
            # 步骤2: 创建Release
            print("创建新Release...")
            create_url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases"
            release_data = {
                'tag_name': VERSION,
                'name': f'Model Files for {VERSION}',
                'body': '''This release contains the Siamese model file required for the nine-grid verification system.

## Model Information
- **File**: best_siamese_model.pth
- **Size**: 137.44 MB
- **Accuracy**: 98.88%
- **Purpose**: Nine-grid image recognition for Geetest verification

## Installation
1. Download the model file from this release
2. Place it in the root directory of GrabOrderApp
3. Build the APK normally

## Note
This file is too large to be included in the git repository, so it's hosted separately in this release.''',
                'draft': False,
                'prerelease': False
            }
            
            response = requests.post(create_url, json=release_data, headers=headers)
            
            if response.status_code == 201:
                release = response.json()
                release_id = release['id']
                upload_url = release['upload_url'].replace('{?name,label}', '')
                print(f"✅ Release创建成功 (ID: {release_id})")
            else:
                print(f"❌ 创建Release失败: {response.status_code}")
                print(f"   {response.text}")
                return False
        
        # 步骤3: 检查文件是否已上传
        print("检查文件是否已上传...")
        assets_url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/{release_id}/assets"
        response = requests.get(assets_url, headers=headers)
        
        if response.status_code == 200:
            assets = response.json()
            for asset in assets:
                if asset['name'] == MODEL_FILE:
                    print(f"⚠️  文件已存在，删除旧文件...")
                    delete_url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/assets/{asset['id']}"
                    requests.delete(delete_url, headers=headers)
        
        # 步骤4: 上传文件
        print(f"上传 {MODEL_FILE}...")
        upload_headers = {
            'Authorization': f'token {token}',
            'Content-Type': 'application/octet-stream',
        }
        
        upload_url = f"{upload_url}?name={MODEL_FILE}"
        
        with open(MODEL_FILE, 'rb') as f:
            response = requests.post(upload_url, data=f, headers=upload_headers)
        
        if response.status_code == 201:
            asset = response.json()
            download_url = asset['browser_download_url']
            print(f"✅ 上传成功!")
            print(f"")
            print(f"📥 下载URL:")
            print(f"   {download_url}")
            return True
        else:
            print(f"❌ 上传失败: {response.status_code}")
            print(f"   {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ 发生错误: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # 从命令行参数获取token
        create_release_and_upload(sys.argv[1])
    else:
        # 从环境变量获取token
        create_release_and_upload()
