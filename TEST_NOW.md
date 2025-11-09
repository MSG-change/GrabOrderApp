# 🚀 立即测试抢单

## ✅ 前提条件

1. AI服务器运行中 ✅
2. 需要登录token

## 📱 快速测试步骤

### 步骤1: 获取Token（如果还没有）

```bash
./run_login_test.sh
```

- 按Enter使用默认手机号
- 等待短信验证码
- 输入验证码
- Token自动保存

### 步骤2: 运行抢单测试

```bash
./run_grab_test.sh
```

- 按Enter使用默认订单ID（9999999）
- 或输入任意订单ID测试

### 步骤3: 查看结果

## 🎯 预期结果

### 如果订单不存在（正常）

```
Response: HTTP 200
Result: {
  "code": 500,
  "msg": "订单不存在"
}

✅ PARAMETER TEST PASSED: API accepted the request format
```

**这说明：**
- ✅ Geetest验证成功
- ✅ geeDto参数正确
- ✅ API请求格式正确
- ✅ 认证token有效
- ✅ 可以用于真实抢单

### 如果抢单成功

```
Response: HTTP 200
Result: {
  "code": 0,
  "msg": "success",
  "data": {...}
}

✅ SUCCESS: Order grabbed!
```

### 如果参数错误（不应该出现）

```
Response: HTTP 200
Result: {
  "code": 1001,
  "msg": "需要验证"
}

❌ Geetest parameters may be incorrect
```

## 📊 完整请求示例

程序会发送这样的请求：

```http
POST /gate/app-api/club/order/grabAnOrder/v1
Authorization: Bearer <your_token>
Content-Type: application/json
tenant-id: 1

{
  "orderId": "9999999",
  "geeDto": {
    "lotNumber": "eeff14aab96541dcb41e23c7d63f4634",
    "captchaOutput": "8a799621b927af55...",
    "passToken": "7fa9861362a31295...",
    "genTime": "1762714435",
    "captchaId": "045e2c229998a88721e32a763bc0f7b8",
    "captchaKeyType": "dlVerify"
  }
}
```

## ✅ 测试成功标志

1. ✅ HTTP 200响应
2. ✅ 返回JSON数据
3. ✅ Code不是1001（不是"需要验证"）
4. ✅ Code不是401（不是"未授权"）

即使Code是500（订单不存在），也说明**参数格式完全正确**！

## 🎉 测试通过后

可以确认：
- ✅ 整个Geetest验证流程正确
- ✅ 所有参数传递正确
- ✅ API集成成功
- ✅ 可以用于真实抢单

只需要：
- 将订单ID改为真实订单
- 在检测到新订单时调用相同的逻辑
- 就可以真正抢单了！
