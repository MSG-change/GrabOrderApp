#!/usr/bin/env python3
"""
私有模型存储配置
使用私有云存储服务托管模型文件
"""

# 选项1: 使用私有GitHub Gist
GITHUB_GIST_CONFIG = {
    "gist_id": "YOUR_PRIVATE_GIST_ID",  # 创建私有Gist后的ID
    "raw_url": "https://gist.githubusercontent.com/MSG-change/GIST_ID/raw/best_siamese_model.pth",
    "requires_token": True,  # 私有Gist需要token访问
}

# 选项2: 使用阿里云OSS私有存储
ALIYUN_OSS_CONFIG = {
    "endpoint": "oss-cn-shanghai.aliyuncs.com",
    "bucket": "your-private-bucket",
    "key": "models/best_siamese_model.pth",
    "access_key_id": "YOUR_ACCESS_KEY",
    "access_key_secret": "YOUR_SECRET_KEY",
    "expires": 3600,  # 签名URL有效期（秒）
}

# 选项3: 使用腾讯云COS
TENCENT_COS_CONFIG = {
    "region": "ap-shanghai",
    "bucket": "your-bucket-123456",
    "key": "models/best_siamese_model.pth",
    "secret_id": "YOUR_SECRET_ID",
    "secret_key": "YOUR_SECRET_KEY",
}

# 选项4: 使用Google Drive（需要认证）
GOOGLE_DRIVE_CONFIG = {
    "file_id": "YOUR_FILE_ID",  # 从分享链接提取
    "download_url": "https://drive.google.com/uc?export=download&id=FILE_ID",
    "requires_auth": False,  # 可以设置为"任何人有链接可查看"
}

# 选项5: 使用私有服务器
PRIVATE_SERVER_CONFIG = {
    "url": "https://your-server.com/private/models/best_siamese_model.pth",
    "auth_type": "basic",  # basic, token, or api_key
    "username": "YOUR_USERNAME",
    "password": "YOUR_PASSWORD",
}

# 选项6: 使用加密的公开存储
ENCRYPTED_PUBLIC_CONFIG = {
    "url": "https://github.com/MSG-change/GrabOrderApp/releases/download/v1.7.2/model.enc",
    "encryption": "AES256",
    "password": "YOUR_DECRYPTION_PASSWORD",
}


def download_private_model(storage_type="github_gist"):
    """
    从私有存储下载模型
    """
    import os
    import requests
    
    if storage_type == "github_gist":
        # 使用私有Gist
        token = os.environ.get('GITHUB_TOKEN')
        if not token:
            print("❌ 需要GITHUB_TOKEN访问私有Gist")
            return False
            
        headers = {'Authorization': f'token {token}'}
        response = requests.get(GITHUB_GIST_CONFIG['raw_url'], headers=headers)
        
    elif storage_type == "aliyun_oss":
        # 使用阿里云OSS
        from aliyunsdkcore.client import AcsClient
        from aliyunsdkoss.request.v20190517 import GeneratePresignedUrlRequest
        
        client = AcsClient(
            ALIYUN_OSS_CONFIG['access_key_id'],
            ALIYUN_OSS_CONFIG['access_key_secret'],
            ALIYUN_OSS_CONFIG['endpoint']
        )
        
        # 生成签名URL
        request = GeneratePresignedUrlRequest()
        request.set_Bucket(ALIYUN_OSS_CONFIG['bucket'])
        request.set_Key(ALIYUN_OSS_CONFIG['key'])
        request.set_Expires(ALIYUN_OSS_CONFIG['expires'])
        
        response = client.do_action_with_exception(request)
        signed_url = response
        
        # 下载文件
        response = requests.get(signed_url)
        
    elif storage_type == "google_drive":
        # 使用Google Drive
        url = GOOGLE_DRIVE_CONFIG['download_url']
        response = requests.get(url, stream=True)
        
    elif storage_type == "private_server":
        # 使用私有服务器
        auth = (
            PRIVATE_SERVER_CONFIG['username'],
            PRIVATE_SERVER_CONFIG['password']
        )
        response = requests.get(
            PRIVATE_SERVER_CONFIG['url'],
            auth=auth
        )
        
    else:
        print(f"❌ 不支持的存储类型: {storage_type}")
        return False
    
    # 保存文件
    if response.status_code == 200:
        with open("best_siamese_model.pth", "wb") as f:
            f.write(response.content)
        print("✅ 模型下载成功")
        return True
    else:
        print(f"❌ 下载失败: {response.status_code}")
        return False


if __name__ == "__main__":
    import sys
    storage_type = sys.argv[1] if len(sys.argv) > 1 else "github_gist"
    download_private_model(storage_type)
