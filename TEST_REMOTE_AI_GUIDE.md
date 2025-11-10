# 🤖 远程 AI 测试指南

## 📋 测试脚本说明

### 1. test_remote_ai_api.py - 直接测试 AI API

**功能**: 直接调用远程 AI API 识别验证码

**使用方法**:
```bash
# 测试健康检查
python test_remote_ai_api.py

# 测试识别功能（需要真实的图片URL）
python test_remote_ai_api.py \
  "https://gcaptcha4.geetest.com/load?..." \
  "https://gcaptcha4.geetest.com/pictures/..."
```

### 2. test_login_with_remote_ai.py - 完整登录流程测试

**功能**: 测试手机号登录 + 远程AI识别九宫格验证码的完整流程

**使用方法**:
```bash
python test_login_with_remote_ai.py
# 然后按提示输入手机号和短信验证码
```

### 3. test_grab_with_ai.py - 基础功能测试

**功能**: 测试模块导入和AI服务器连接

**使用方法**:
```bash
python test_grab_with_ai.py
```

## 🚀 完整测试流程

### 方法A: 使用手机号登录测试（推荐）

```bash
# 1. 运行登录测试脚本
python test_login_with_remote_ai.py

# 2. 输入手机号（例如: 13800138000）

# 3. 等待短信验证码

# 4. 脚本会自动:
#    - 发送短信
#    - 获取极验 Challenge
#    - 调用远程AI识别九宫格
#    - 等待您输入短信验证码
#    - 完成登录

# 5. 查看测试结果
```

### 方法B: 直接测试 AI API

如果您已经有验证码图片URL:

```bash
python test_remote_ai_api.py \
  "问题图片URL" \
  "九宫格图片URL"
```

## 📝 获取验证码图片URL的方法

### 方法1: 从浏览器开发者工具

1. 打开浏览器开发者工具 (F12)
2. 切换到 Network 标签
3. 触发验证码
4. 查找图片请求，复制URL

### 方法2: 从登录流程日志

运行登录测试时，日志会显示图片URL:

```bash
python test_login_with_remote_ai.py
# 查看日志中的图片URL
```

### 方法3: 使用 GeetestHelper

```python
from libs.geetest_helper_local import GeetestHelper
import os

os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'

helper = GeetestHelper()
result = helper.verify("your_challenge_here")
# 查看日志获取图片URL
```

## 🔍 测试验证点

### ✅ 必须通过的测试

1. **健康检查**
   ```bash
   curl http://154.219.127.13:8889/health
   ```
   预期: `{"status":"ok","model_loaded":true}`

2. **模块导入**
   ```bash
   python test_grab_with_ai.py
   ```
   预期: 所有测试通过

3. **AI识别**
   ```bash
   python test_remote_ai_api.py <question_url> <grid_url>
   ```
   预期: 返回识别结果 `[0, 1, 2]` 等

4. **完整登录**
   ```bash
   python test_login_with_remote_ai.py
   ```
   预期: 登录成功并获得 token

## 📊 测试结果示例

### 成功的识别结果

```json
{
  "success": true,
  "answers": [1, 3, 5],
  "predictions": [
    {"index": 0, "score": 0.2345},
    {"index": 1, "score": 0.8765},
    {"index": 2, "score": 0.3456},
    {"index": 3, "score": 0.9123},
    {"index": 4, "score": 0.1234},
    {"index": 5, "score": 0.8901},
    {"index": 6, "score": 0.2345},
    {"index": 7, "score": 0.3456},
    {"index": 8, "score": 0.4567}
  ],
  "threshold": 0.5
}
```

### 成功的登录结果

```json
{
  "code": 0,
  "msg": "success",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "userInfo": {...}
  }
}
```

## 🐛 常见问题

### 问题1: AI服务器连接失败

**检查**:
```bash
curl http://154.219.127.13:8889/health
```

**解决**:
- 检查服务器IP是否正确
- 检查防火墙是否开放8889端口
- 检查Docker容器是否运行: `docker ps | grep geetest-ai`

### 问题2: 模块导入失败

**错误**: `ModuleNotFoundError: No module named 'xxx'`

**解决**:
```bash
cd /Users/duanzubin/develop/script/siam-autolabel/GrabOrderApp
pip install -r requirements.txt
```

### 问题3: 验证码识别失败

**检查**:
1. 图片URL是否可访问
2. 图片格式是否正确
3. AI服务器日志: `docker logs geetest-ai`

### 问题4: 登录失败

**可能原因**:
- 短信验证码错误
- 验证码识别结果不正确
- Challenge 已过期

**解决**: 重新运行测试脚本

## 📞 技术支持

如遇问题，请提供:
1. 测试脚本输出的完整日志
2. AI服务器日志: `docker logs geetest-ai`
3. 错误截图

## 🎯 下一步

测试通过后，您可以:
1. 在实际抢单APP中使用远程AI
2. 打包成Android APK
3. 部署到生产环境

---

**AI 服务器**: http://154.219.127.13:8889  
**状态**: ✅ 在线运行
