# 登录验证码测试指南

## 🎯 **测试目标**

测试登录时的Geetest验证码流程：
1. 点击"发送验证码"触发Geetest
2. AI识别九宫格
3. 发送短信验证码
4. 输入验证码登录

## 📱 **测试方式**

### 方式A：本地测试（推荐）

```bash
# 1. 启动AI服务器
cd /Users/duanzubin/develop/script/siam-autolabel/geetest_ai
export AI_SERVER_URL=http://127.0.0.1:8889
python3 api_server.py

# 2. 新终端：运行测试APP
cd /Users/duanzubin/develop/script/siam-autolabel/GrabOrderApp
export AI_SERVER_URL=http://127.0.0.1:8889
python3 test_login_ui.py
```

### 方式B：手机测试

```bash
# 1. 构建APK
cd /Users/duanzubin/develop/script/siam-autolabel/GrabOrderApp
buildozer -v android debug

# 2. 安装到手机
adb install -r bin/logintest-1.0.0-arm64-v8a-debug.apk

# 3. 设置AI服务器（如果使用远程AI）
# 在代码中修改AI_SERVER_URL
```

## 🔍 **测试流程**

### 步骤1: 发送验证码

```
用户操作：
1. 输入手机号（默认：18113011654）
2. 点击"Send Code"按钮

APP执行：
1. 生成challenge（基于手机号+时间戳）
2. Load - 获取验证码数据
   GET /load?captcha_id=...&challenge=...
3. 识别九宫格（调用AI服务器）
4. 生成W参数
5. Verify - 验证
   GET /verify?lot_number=...&w=...
6. 发送短信验证码
   POST /sendLoginCode
   {
     "mobile": "18113011654",
     "lotNumber": "...",
     "captchaOutput": "...",
     "passToken": "...",
     "genTime": "...",
     "captchaId": "045e2c229998a88721e32a763bc0f7b8",
     "captchaKeyType": "dlVerify"
   }

预期结果：
✅ 收到短信验证码
```

### 步骤2: 登录

```
用户操作：
1. 输入收到的短信验证码
2. 点击"Login"按钮

APP执行：
POST /login
{
  "mobile": "18113011654",
  "code": "123456",
  "loginType": "sms"
}

预期结果：
✅ 登录成功
✅ 获得token
✅ token保存到文件
```

## 📊 **日志示例**

### 成功的日志

```
[10:20:30] Initializing Geetest helper...
[10:20:31] AI Server: http://127.0.0.1:8889
[10:20:31] Geetest helper initialized
[10:20:31] Ready to test!
[10:20:35] ==================================================
[10:20:35] Step 1: Sending SMS code...
[10:20:35] Performing Geetest verification...
[10:20:35] Challenge: send_18113011654_1762712400...
[10:20:36] Answers: [2, 5, 7]
[10:20:36] Geetest verification success!
[10:20:36] Sending SMS code...
[10:20:36] Request: POST https://dysh.dyswl.com/gate/app-api/club/auth/sendLoginCode
[10:20:37] Response: HTTP 200
[10:20:37] Result: {'code': 0, 'msg': 'success'}
[10:20:37] SUCCESS: SMS code sent!
[10:20:37] Please check your phone
[10:21:00] ==================================================
[10:21:00] Step 2: Logging in...
[10:21:00] Request: POST https://dysh.dyswl.com/gate/app-api/club/auth/login
[10:21:01] Response: HTTP 200
[10:21:01] Result: {'code': 0, 'data': {'token': 'eyJhbGc...'}}
[10:21:01] SUCCESS: Login successful!
[10:21:01] Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOi...
[10:21:01] Saved: login_token_1762712461.txt
```

### 失败的日志（需要排查）

```
[10:20:35] Error: Geetest verification failed
→ 检查AI服务器是否运行
→ 检查网络连接

[10:20:37] Error: 验证码错误
→ 检查geeDto参数是否正确
→ 检查lot_number是否匹配

[10:21:01] Error: 验证码已过期
→ 验证码有效期通常60-120秒
→ 需要重新发送
```

## 🔧 **关键代码**

### test_login_ui.py

```python
# 发送验证码流程
def _send_code_thread(self, phone):
    # 1. Geetest验证
    challenge = self.geetest_helper.generate_challenge(f"send_{phone}_{time.time()}")
    geetest_result = self.geetest_helper.verify(challenge=challenge)
    
    # 2. 发送短信
    send_data = {
        'mobile': phone,
        'lotNumber': geetest_result['lot_number'],
        'captchaOutput': geetest_result['captcha_output'],
        'passToken': geetest_result['pass_token'],
        'genTime': str(geetest_result['gen_time']),
        'captchaId': '045e2c229998a88721e32a763bc0f7b8',
        'captchaKeyType': 'dlVerify'
    }
    response = self.session.post(send_code_url, json=send_data)
```

### libs/geetest_helper_local.py

```python
# 完整验证流程
def verify(self, challenge):
    # Load → 识别 → 生成W → Verify
    load_data = load(captcha_id, challenge)
    answers = recognize(imgs, ques)
    w_param = generate_w(lot_number, answers)
    verify_result = verify(lot_number, w_param)
    
    return {
        'success': True,
        'lot_number': lot_number,
        'captcha_output': w_param,
        'pass_token': pass_token,
        'answers': answers
    }
```

## 🎯 **验证点**

### 1. Geetest流程正确性

- [ ] Load请求成功（获取lot_number）
- [ ] 识别成功（返回3个索引）
- [ ] W参数生成成功
- [ ] Verify请求成功（获取pass_token）

### 2. 数据一致性

- [ ] lot_number在整个流程中保持一致
- [ ] payload、process_token来自同一个Load
- [ ] W参数基于正确的lot_number生成

### 3. API请求正确性

- [ ] sendLoginCode请求包含完整的geeDto
- [ ] geeDto结构正确
- [ ] 所有必需字段都存在

### 4. 时效性

- [ ] Load到Verify在60秒内完成
- [ ] Verify到发送短信在60秒内完成
- [ ] 短信验证码在5分钟内使用

## 🐛 **常见问题**

### 问题1: AI服务器连接失败

```
Error: Connection refused
```

**解决：**
```bash
# 检查AI服务器是否运行
ps aux | grep api_server

# 启动AI服务器
cd /Users/duanzubin/develop/script/siam-autolabel/geetest_ai
python3 api_server.py
```

### 问题2: 验证码识别失败

```
Error: Recognition failed
```

**解决：**
- 检查模型文件是否存在
- 检查图片URL是否可访问
- 查看AI服务器日志

### 问题3: 验证失败

```
Error: Verify failed
```

**解决：**
- 检查lot_number是否正确
- 检查W参数是否正确
- 检查payload、process_token是否匹配

### 问题4: 发送短信失败

```
Error: 验证码错误
```

**解决：**
- 检查geeDto参数是否完整
- 检查captchaId是否正确
- 检查时效性（是否超时）

## 📝 **测试检查清单**

### 准备阶段
- [ ] AI服务器已启动
- [ ] 模型文件存在
- [ ] 网络连接正常
- [ ] 手机号正确

### 测试阶段
- [ ] 点击"Send Code"
- [ ] 观察日志输出
- [ ] 检查Geetest验证成功
- [ ] 确认收到短信
- [ ] 输入验证码
- [ ] 点击"Login"
- [ ] 确认登录成功
- [ ] 检查token保存

### 验证阶段
- [ ] 日志无错误
- [ ] 所有步骤成功
- [ ] token有效
- [ ] 可以用token访问API

## 🚀 **快速测试命令**

```bash
# 一键测试（本地）
cd /Users/duanzubin/develop/script/siam-autolabel/GrabOrderApp
export AI_SERVER_URL=http://127.0.0.1:8889
python3 test_login_ui.py

# 构建APK（手机测试）
buildozer -v android debug

# 安装APK
adb install -r bin/logintest-1.0.0-arm64-v8a-debug.apk

# 查看日志
adb logcat | grep python
```

## 📊 **性能指标**

| 步骤 | 预期耗时 | 说明 |
|------|----------|------|
| Load | ~300ms | 获取验证码数据 |
| 识别 | ~500ms | AI识别九宫格 |
| 生成W | ~100ms | 本地计算 |
| Verify | ~200ms | 验证W参数 |
| 发送短信 | ~500ms | API请求 |
| **总计** | **~1.6s** | 从点击到发送成功 |

## ✅ **成功标准**

1. ✅ Geetest验证成功率 > 95%
2. ✅ 短信发送成功率 > 95%
3. ✅ 登录成功率 > 95%
4. ✅ 总耗时 < 3秒
5. ✅ UI无卡顿
6. ✅ 无中文乱码
7. ✅ 日志清晰可读

## 🎉 **测试完成后**

如果测试成功，说明：
1. ✅ Geetest验证流程正确
2. ✅ AI识别准确
3. ✅ 数据传递正确
4. ✅ API集成成功

可以将相同的逻辑应用到抢单流程！
