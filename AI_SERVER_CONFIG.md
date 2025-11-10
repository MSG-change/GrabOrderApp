# 🌐 AI服务器配置指南

## 📍 云服务器地址

```
IP: 154.219.127.13
端口: 8889
完整地址: http://154.219.127.13:8889
```

## 🔧 配置方法

### 方法1: 环境变量（推荐）

在运行APP前设置环境变量：

```bash
# 设置AI服务器地址
export AI_SERVER_URL=http://154.219.127.13:8889

# 运行APP
python main.py
```

### 方法2: 修改代码

在 `libs/geetest_helper_local.py` 中：

```python
# 第73行附近
ai_server_url = os.environ.get('AI_SERVER_URL', 'http://154.219.127.13:8889')
```

### 方法3: 启动脚本

创建 `start_app.sh`:

```bash
#!/bin/bash
export AI_SERVER_URL=http://154.219.127.13:8889
python main.py
```

## 📱 Android APK配置

### 在buildozer.spec中添加：

```ini
[app]
# 环境变量
p4a.bootstrap = sdl2
android.permissions = INTERNET
android.meta_data = AI_SERVER_URL=http://154.219.127.13:8889
```

### 或在main.py开头添加：

```python
import os
os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'
```

## ✅ 验证配置

运行测试脚本：

```bash
export AI_SERVER_URL=http://154.219.127.13:8889
python test_geetest_remote.py
```

预期输出：
```
🌐 使用远程AI服务: http://154.219.127.13:8889
✅ 远程识别成功: [0, 1, 2]
```

## 🔍 检查服务状态

```bash
# 健康检查
curl http://154.219.127.13:8889/health

# 应该返回：
# {"status":"ok","model_type":"GeetestRecognizer","accuracy":0.9888}
```

## 📝 当前配置

- **开发环境**: 使用环境变量 `AI_SERVER_URL`
- **生产环境**: 打包到APK中
- **默认值**: 如果未配置，使用本地模型

## 🚀 快速开始

```bash
# 1. 设置服务器地址
export AI_SERVER_URL=http://154.219.127.13:8889

# 2. 运行测试
cd /Users/duanzubin/develop/script/siam-autolabel/GrabOrderApp
./run_grab_test.sh

# 3. 运行APP
python main.py
```
