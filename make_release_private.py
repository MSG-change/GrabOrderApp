#!/usr/bin/env python3
"""
将Release设置为草稿或删除敏感文件
"""

import os
import sys
import requests

def manage_release(token, action="draft"):
    """
    管理Release的可见性
    
    Args:
        token: GitHub Token
        action: "draft" (设为草稿), "delete" (删除), "remove_asset" (只删除文件)
    """
    OWNER = "MSG-change"
    REPO = "GrabOrderApp"
    VERSION = "v1.7.2"
    
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
    }
    
    # 获取Release信息
    get_url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/tags/{VERSION}"
    response = requests.get(get_url, headers=headers)
    
    if response.status_code != 200:
        print(f"❌ 无法获取Release: {response.status_code}")
        return False
    
    release = response.json()
    release_id = release['id']
    
    if action == "draft":
        # 将Release设为草稿（隐藏）
        update_url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/{release_id}"
        update_data = {
            'draft': True,  # 设为草稿
            'prerelease': False
        }
        
        response = requests.patch(update_url, json=update_data, headers=headers)
        
        if response.status_code == 200:
            print("✅ Release已设为草稿（隐藏）")
            print("   只有你能看到这个Release")
            return True
        else:
            print(f"❌ 更新失败: {response.status_code}")
            return False
            
    elif action == "delete":
        # 完全删除Release
        delete_url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/{release_id}"
        response = requests.delete(delete_url, headers=headers)
        
        if response.status_code == 204:
            print("✅ Release已删除")
            return True
        else:
            print(f"❌ 删除失败: {response.status_code}")
            return False
            
    elif action == "remove_asset":
        # 只删除模型文件，保留Release
        assets_url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/{release_id}/assets"
        response = requests.get(assets_url, headers=headers)
        
        if response.status_code == 200:
            assets = response.json()
            for asset in assets:
                if asset['name'] == "best_siamese_model.pth":
                    delete_url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/assets/{asset['id']}"
                    response = requests.delete(delete_url, headers=headers)
                    
                    if response.status_code == 204:
                        print(f"✅ 已删除文件: {asset['name']}")
                        return True
                    else:
                        print(f"❌ 删除文件失败: {response.status_code}")
                        return False
            
            print("⚠️  未找到模型文件")
            return False


if __name__ == "__main__":
    token = os.environ.get('GITHUB_TOKEN')
    
    if not token:
        print("❌ 需要GitHub Token")
        print("使用方法:")
        print("  export GITHUB_TOKEN=your_token")
        print("  python make_release_private.py [draft|delete|remove_asset]")
        sys.exit(1)
    
    action = sys.argv[1] if len(sys.argv) > 1 else "draft"
    
    print(f"🔧 执行操作: {action}")
    manage_release(token, action)
