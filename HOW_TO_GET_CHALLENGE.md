# 📖 如何获取 Challenge

## 方法1: 使用 curl 命令（推荐）

```bash
curl -X POST https://app.shunshunxiaozhan.com/driver/user/getGeetestChallenge \
  -H 'Content-Type: application/json' \
  -d '{"phone":"18113011654","captchaId":"045e2c229998a88721e32a763bc0f7b8"}'
```

**返回示例：**
```json
{
  "code": 0,
  "msg": "success",
  "data": {
    "challenge": "abc123def456...",
    "lot_number": "xyz789..."
  }
}
```

**提取 challenge：**
从返回的 JSON 中复制 `data.challenge` 的值

## 方法2: 使用 Postman

1. 打开 Postman
2. 创建新的 POST 请求
3. URL: `https://app.shunshunxiaozhan.com/driver/user/getGeetestChallenge`
4. Headers: 
   - `Content-Type: application/json`
5. Body (raw JSON):
   ```json
   {
     "phone": "18113011654",
     "captchaId": "045e2c229998a88721e32a763bc0f7b8"
   }
   ```
6. 点击 Send
7. 从响应中复制 `challenge` 值

## 方法3: 使用浏览器开发者工具

1. 打开浏览器（Chrome/Firefox）
2. 按 F12 打开开发者工具
3. 切换到 Network 标签
4. 在 APP 或网页中触发登录
5. 查找 `getGeetestChallenge` 请求
6. 查看响应，复制 `challenge` 值

## 方法4: 使用 Python 脚本

```python
import requests

url = "https://app.shunshunxiaozhan.com/driver/user/getGeetestChallenge"
data = {
    "phone": "18113011654",
    "captchaId": "045e2c229998a88721e32a763bc0f7b8"
}

response = requests.post(url, json=data)
result = response.json()

if result['code'] == 0:
    challenge = result['data']['challenge']
    print(f"Challenge: {challenge}")
else:
    print(f"Error: {result['msg']}")
```

## 获取到 Challenge 后

### 方法A: 使用命令行参数

```bash
python test_ai_with_challenge.py 'your_challenge_here'
```

### 方法B: 使用交互式脚本

```bash
python test_ai_manual.py
# 然后粘贴 challenge
```

## 完整测试示例

```bash
# 1. 获取 challenge（使用 curl）
CHALLENGE=$(curl -s -X POST https://app.shunshunxiaozhan.com/driver/user/getGeetestChallenge \
  -H 'Content-Type: application/json' \
  -d '{"phone":"18113011654","captchaId":"045e2c229998a88721e32a763bc0f7b8"}' \
  | grep -o '"challenge":"[^"]*"' | cut -d'"' -f4)

echo "Challenge: $CHALLENGE"

# 2. 测试远程 AI
python test_ai_with_challenge.py "$CHALLENGE"
```

## 注意事项

1. **Challenge 有效期**
   - 通常几分钟内有效
   - 过期后需要重新获取

2. **手机号**
   - 使用您的真实手机号: `18113011654`
   - 确保手机号格式正确

3. **Captcha ID**
   - 固定值: `045e2c229998a88721e32a763bc0f7b8`
   - 通常不需要修改

## 故障排查

### 问题1: 网络连接失败

**解决：**
- 检查网络连接
- 尝试使用 VPN
- 使用手机热点

### 问题2: 返回错误码

**常见错误：**
- `code: 1001` - 手机号格式错误
- `code: 1002` - 参数缺失
- `code: 5000` - 服务器错误

### 问题3: Challenge 无效

**解决：**
- 重新获取 challenge
- 确保 challenge 完整（没有截断）
- 检查是否过期

## 快速测试流程

```bash
# 手动输入方式（推荐）
python test_ai_manual.py

# 然后按提示：
# 1. 粘贴 challenge
# 2. 回车（使用默认 captcha_id）
# 3. 等待识别结果
```

---

**您的手机号**: 18113011654  
**Captcha ID**: 045e2c229998a88721e32a763bc0f7b8  
**AI 服务器**: http://154.219.127.13:8889
