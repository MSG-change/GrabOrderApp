# 🔧 远程 AI 集成指南

## 核心概念

**您不需要手动传 challenge！**

`GeetestHelper` 会自动完成以下步骤：
1. ✅ 接收 challenge 参数
2. ✅ 获取验证码图片
3. ✅ 调用远程 AI 识别
4. ✅ 返回完整的验证结果

## 📝 在 APP 中的使用流程

### 完整流程图

```
用户操作
   ↓
需要验证码（登录/抢单）
   ↓
调用 API 获取 challenge ← APP 自动完成
   ↓
传给 GeetestHelper.verify(challenge)
   ↓
GeetestHelper 自动：
  - 获取图片
  - 调用远程 AI (http://154.219.127.13:8889)
  - 识别验证码
   ↓
返回 geeDto
   ↓
用于登录/抢单
```

## 💻 代码示例

### 示例1: 在现有代码中使用

```python
import os
os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'

from libs.geetest_helper_local import GeetestHelper

# 初始化（只需一次）
helper = GeetestHelper(captcha_id="045e2c229998a88721e32a763bc0f7b8")

# 使用（每次需要验证码时）
def need_geetest_verification(challenge):
    """
    当需要验证码时调用
    
    Args:
        challenge: 从 API 返回的 challenge 字符串
    
    Returns:
        geeDto 字典，可直接用于请求
    """
    # 调用 verify，远程 AI 自动识别
    result = helper.verify(challenge)
    
    if result and result.get('success'):
        # 返回 geeDto
        return {
            'lotNumber': result['lot_number'],
            'captchaOutput': result['captcha_output'],
            'passToken': result['pass_token'],
            'genTime': result['gen_time'],
            'captchaId': "045e2c229998a88721e32a763bc0f7b8",
            'captchaKeyType': 'dlVerify'
        }
    else:
        return None
```

### 示例2: 登录流程

```python
def login_process(phone, sms_code):
    """登录流程"""
    
    # 1. 获取 challenge（调用您的 API）
    challenge_response = requests.post(
        "https://app.shunshunxiaozhan.com/driver/user/getGeetestChallenge",
        json={"phone": phone, "captchaId": "045e2c229998a88721e32a763bc0f7b8"}
    )
    challenge = challenge_response.json()['data']['challenge']
    
    # 2. 使用 GeetestHelper 识别（远程 AI 自动完成）
    helper = GeetestHelper()
    geetest_result = helper.verify(challenge)  # ← 这里自动调用远程 AI
    
    # 3. 构造 geeDto
    gee_dto = {
        'lotNumber': geetest_result['lot_number'],
        'captchaOutput': geetest_result['captcha_output'],
        'passToken': geetest_result['pass_token'],
        'genTime': geetest_result['gen_time'],
        'captchaId': "045e2c229998a88721e32a763bc0f7b8",
        'captchaKeyType': 'dlVerify'
    }
    
    # 4. 登录
    login_response = requests.post(
        "https://app.shunshunxiaozhan.com/driver/user/loginBySms",
        json={
            "phone": phone,
            "code": sms_code,
            "geeDto": gee_dto
        }
    )
    
    return login_response.json()
```

### 示例3: 抢单流程

```python
def grab_order_process(order_id, token):
    """抢单流程"""
    
    helper = GeetestHelper()
    
    # 1. 先尝试直接抢单
    response = requests.post(
        "https://app.shunshunxiaozhan.com/driver/order/grab",
        json={"orderId": order_id},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    result = response.json()
    
    # 2. 如果需要验证码
    if result.get('code') == 4001:  # 假设这是需要验证码的错误码
        challenge = result['data']['challenge']
        
        # 3. 使用远程 AI 识别
        geetest_result = helper.verify(challenge)  # ← 自动调用远程 AI
        
        if geetest_result and geetest_result.get('success'):
            # 4. 带验证码重新抢单
            gee_dto = {
                'lotNumber': geetest_result['lot_number'],
                'captchaOutput': geetest_result['captcha_output'],
                'passToken': geetest_result['pass_token'],
                'genTime': geetest_result['gen_time'],
                'captchaId': "045e2c229998a88721e32a763bc0f7b8",
                'captchaKeyType': 'dlVerify'
            }
            
            response = requests.post(
                "https://app.shunshunxiaozhan.com/driver/order/grab",
                json={"orderId": order_id, "geeDto": gee_dto},
                headers={"Authorization": f"Bearer {token}"}
            )
    
    return response.json()
```

## 🔑 关键点

### 1. 环境变量配置

在 `main.py` 开头已经配置：
```python
os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'
```

### 2. challenge 从哪里来？

**从您的 API 返回中获取！**

例如：
- 登录时：`getGeetestChallenge` 接口返回
- 抢单时：第一次抢单失败的错误响应中返回

### 3. 不需要手动处理图片

`GeetestHelper.verify(challenge)` 内部会：
- 自动构造图片 URL
- 自动下载图片
- 自动调用远程 AI
- 自动返回结果

### 4. 返回的结果包含什么？

```python
{
    'success': True,
    'lot_number': '...',
    'pass_token': '...',
    'captcha_output': '...',  # W 参数
    'gen_time': '...',
    'answers': [1, 3, 5]  # 识别的答案（可选）
}
```

## 📱 在 Android APK 中使用

完全相同！因为：
1. ✅ `main.py` 已配置 AI 服务器地址
2. ✅ `GeetestHelper` 会自动使用远程 AI
3. ✅ 打包成 APK 后自动生效

## 🔍 调试技巧

### 查看是否使用远程 AI

```python
helper = GeetestHelper()
print(f"使用远程AI: {helper.model is None}")  # True 表示使用远程 AI
```

### 查看识别过程

运行时会自动打印日志：
```
🔧 初始化 Geetest 验证器...
   🌐 已配置远程AI服务，跳过本地模型加载
   ✅ 初始化完成
正在识别验证码...
   🌐 使用远程AI服务: http://154.219.127.13:8889
   ✅ 远程识别成功: [1, 3, 5]
```

## ✅ 检查清单

- [ ] `main.py` 中已设置 `AI_SERVER_URL`
- [ ] 导入 `GeetestHelper`
- [ ] 从 API 获取 `challenge`
- [ ] 调用 `helper.verify(challenge)`
- [ ] 使用返回的 `geeDto` 进行登录/抢单

## 🎯 总结

**您只需要做两件事：**

1. 从 API 获取 `challenge`
2. 调用 `helper.verify(challenge)`

**其他一切都是自动的：**
- ✅ 获取图片
- ✅ 调用远程 AI
- ✅ 识别验证码
- ✅ 返回结果

---

**AI 服务器**: http://154.219.127.13:8889  
**状态**: ✅ 在线运行  
**无需手动传值，全自动识别！**
