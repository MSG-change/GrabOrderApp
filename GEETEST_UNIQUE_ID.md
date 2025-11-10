# Geetest验证码唯一性识别机制

## 🔑 **核心问题**

**每次Load产生的验证码都不一样，如何确保识别的是正确的那一个？**

## 📊 **唯一标识符体系**

### 1. **lot_number（批次号）** - 最重要！

每次Load请求都会生成一个**唯一的lot_number**，这是验证码的唯一标识。

```
第1次Load:
  lot_number: "eb6e3c4b6c8f44a7a75a062a25455ebe"
  imgs: "captcha_v4/.../xxx1.jpg"
  ques: ["nerualpic/.../yyy1.png"]

第2次Load:
  lot_number: "59063fdc514c4db9a3ccebd951ae5e03"  ← 不同！
  imgs: "captcha_v4/.../xxx2.jpg"  ← 不同的图片！
  ques: ["nerualpic/.../yyy2.png"]  ← 不同的问题！
```

### 2. **完整的数据流**

```
┌─────────────────────────────────────────────────────────────┐
│ Load请求                                                     │
│ GET /load?captcha_id=...&challenge=...                      │
└─────────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────────┐
│ Load返回（包含唯一标识）                                      │
│ {                                                            │
│   "lot_number": "eb6e3c4b...",  ← 唯一标识！                │
│   "imgs": "captcha_v4/.../xxx.jpg",                         │
│   "ques": ["nerualpic/.../yyy.png"],                        │
│   "pow_detail": {...},                                      │
│   "payload": "AgFD8gWU...",  ← 载荷（绑定到lot_number）     │
│   "process_token": "598eda54..."  ← 处理令牌                │
│ }                                                            │
└─────────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────────┐
│ 识别九宫格                                                   │
│ 输入: imgs, ques                                            │
│ 输出: [2, 5, 7]                                             │
└─────────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────────┐
│ 生成W参数（绑定到lot_number）                                │
│ w = generate_w(                                             │
│   lot_number="eb6e3c4b...",  ← 使用这个lot_number！         │
│   pic_index="2,5,7",                                        │
│   ...                                                       │
│ )                                                           │
└─────────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────────┐
│ Verify请求（携带lot_number）                                 │
│ GET /verify?                                                │
│   lot_number=eb6e3c4b...  ← 必须匹配！                      │
│   w=6d9cd699...                                             │
│   payload=AgFD8gWU...  ← 必须是同一个Load返回的！           │
│   process_token=598eda54...  ← 必须是同一个Load返回的！     │
└─────────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────────┐
│ Verify返回（验证通过）                                       │
│ {                                                            │
│   "status": "success",                                      │
│   "data": {                                                 │
│     "result": "success",                                    │
│     "seccode": {                                            │
│       "lot_number": "eb6e3c4b...",  ← 返回相同的！          │
│       "pass_token": "aee8a994...",                          │
│       "captcha_output": "6d9cd699..."                       │
│     }                                                       │
│   }                                                         │
│ }                                                            │
└─────────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────────┐
│ 抢单请求（携带验证结果）                                      │
│ POST /grabAnOrder/v1                                        │
│ {                                                            │
│   "orderId": "3308987",                                     │
│   "geeDto": {                                               │
│     "lotNumber": "eb6e3c4b...",  ← 必须匹配！               │
│     "captchaOutput": "6d9cd699...",                         │
│     "passToken": "aee8a994...",                             │
│     "genTime": "1762711314",                                │
│     "captchaId": "045e2c229998a88721e32a763bc0f7b8",        │
│     "captchaKeyType": "dlVerify"                            │
│   }                                                          │
│ }                                                            │
└─────────────────────────────────────────────────────────────┘
```

## 🔐 **关键绑定关系**

### 1. lot_number是核心

```python
# Load返回
lot_number_1 = "eb6e3c4b6c8f44a7a75a062a25455ebe"
payload_1 = "AgFD8gWU..."
process_token_1 = "598eda54..."

# 这三个是绑定的！
# 如果用错了lot_number，验证会失败
```

### 2. W参数必须匹配lot_number

```python
# 正确：使用同一个lot_number
w = generate_w(
    lot_number="eb6e3c4b...",  # Load返回的
    pic_index="2,5,7",
    ...
)

# 错误：使用了另一个验证码的lot_number
w = generate_w(
    lot_number="59063fdc...",  # ❌ 这是另一个验证码的！
    pic_index="2,5,7",
    ...
)
# 结果：Verify会失败
```

### 3. Verify必须携带完整的Load数据

```python
# 正确：全部来自同一个Load
verify_params = {
    'lot_number': lot_number_1,      # Load返回
    'payload': payload_1,            # Load返回
    'process_token': process_token_1, # Load返回
    'w': w_param                     # 基于lot_number_1生成
}

# 错误：混用了不同Load的数据
verify_params = {
    'lot_number': lot_number_1,      # Load1返回
    'payload': payload_2,            # ❌ Load2返回
    'process_token': process_token_1, # Load1返回
    'w': w_param
}
# 结果：Verify会失败
```

## 🎯 **APP如何正确传递**

### 方案A: 传递captcha_id（推荐）

**APP → AI服务器**
```json
{
  "captcha_id": "045e2c229998a88721e32a763bc0f7b8",
  "challenge": "c9aa9cb8-b6cf-4c26-9812-5453215b2981"
}
```

**AI服务器处理：**
1. 调用Load获取lot_number和图片
2. 识别九宫格
3. 生成W参数（使用这个lot_number）
4. 调用Verify验证
5. 返回完整结果

**AI服务器 → APP**
```json
{
  "success": true,
  "answers": [2, 5, 7],
  "lot_number": "eb6e3c4b...",      // 来自Load
  "captcha_output": "6d9cd699...",  // Verify返回
  "pass_token": "aee8a994...",      // Verify返回
  "gen_time": 1762711314
}
```

**优点：**
- ✅ AI服务器保证数据一致性
- ✅ APP不需要关心lot_number匹配
- ✅ 不会出现混用问题

### 方案B: 传递图片URL（不推荐）

**问题：**
```python
# APP调用Load
load_result_1 = load(captcha_id, challenge_1)
lot_number_1 = load_result_1['lot_number']
imgs_url_1 = load_result_1['imgs']

# APP发送给AI服务器
{
  "question_url": "http://static.geetest.com/xxx1.png",
  "grid_url": "http://static.geetest.com/yyy1.jpg"
}

# AI服务器识别
answers = recognize(question_url, grid_url)  # [2, 5, 7]

# ❌ 问题：AI服务器不知道lot_number！
# APP需要自己生成W参数，但可能已经过期
```

**缺点：**
- ❌ APP需要管理lot_number
- ❌ 可能出现超时（验证码有效期）
- ❌ 容易混用不同验证码的数据

## 💡 **当前实现（正确）**

### libs/geetest_helper_local.py

```python
def verify(self, challenge=None):
    """完整的验证流程"""
    
    # 步骤1: Load - 获取lot_number和图片
    load_response = requests.get(
        "http://gcaptcha4.geetest.com/load",
        params={
            'captcha_id': self.captcha_id,
            'challenge': challenge,
            ...
        }
    )
    load_data = json.loads(load_response.text)
    
    # 保存这个验证码的数据
    lot_number = load_data['data']['lot_number']
    payload = load_data['data']['payload']
    process_token = load_data['data']['process_token']
    imgs_path = load_data['data']['imgs']
    ques_path = load_data['data']['ques'][0]
    
    # 步骤2: 识别（使用这个验证码的图片）
    question_url = f"http://static.geetest.com/{ques_path}"
    grid_url = f"http://static.geetest.com/{imgs_path}"
    answers = self.recognize(question_url, grid_url)
    
    # 步骤3: 生成W参数（使用这个验证码的lot_number）
    w_param = self.w_generator.generate_w(
        lot_number=lot_number,  # ← 使用同一个！
        pic_index=",".join(map(str, answers)),
        ...
    )
    
    # 步骤4: Verify（使用这个验证码的所有数据）
    verify_response = requests.get(
        "http://gcaptcha4.geetest.com/verify",
        params={
            'lot_number': lot_number,      # ← 同一个
            'payload': payload,            # ← 同一个
            'process_token': process_token, # ← 同一个
            'w': w_param,                  # ← 基于同一个lot_number
            ...
        }
    )
    
    # 步骤5: 返回结果（包含lot_number）
    return {
        'success': True,
        'lot_number': lot_number,  # ← 返回给APP
        'captcha_output': w_param,
        'pass_token': pass_token,
        ...
    }
```

### src/fast_grab_service.py

```python
def _grab_with_geetest(self, order_id):
    """抢单流程"""
    
    # 生成challenge（基于订单ID）
    challenge = self.geetest_helper.generate_challenge(str(order_id))
    
    # 调用verify（内部保证数据一致性）
    geetest_result = self.geetest_helper.verify(challenge=challenge)
    
    # 构建geeDto（使用verify返回的lot_number）
    gee_dto = {
        'lotNumber': geetest_result['lot_number'],  # ← 来自verify
        'captchaOutput': geetest_result['captcha_output'],
        'passToken': geetest_result['pass_token'],
        ...
    }
    
    # 发送抢单请求
    response = self.session.post(url, json={
        'orderId': order_id,
        'geeDto': gee_dto  # ← 数据一致
    })
```

## 🔒 **安全机制**

### 1. 时效性
```python
# 验证码有效期：通常60-120秒
# 如果超时，需要重新Load

# Load时间
load_time = "2025-11-10 02:20:00"

# Verify时间
verify_time = "2025-11-10 02:20:05"  # ✅ 5秒内，有效

# 如果
verify_time = "2025-11-10 02:22:00"  # ❌ 2分钟后，可能失效
```

### 2. 一次性
```python
# 每个lot_number只能验证一次
lot_number = "eb6e3c4b..."

# 第一次Verify
verify(lot_number, w_param_1)  # ✅ 成功

# 第二次Verify（相同lot_number）
verify(lot_number, w_param_2)  # ❌ 失败（已使用）
```

### 3. 绑定性
```python
# lot_number与payload、process_token绑定
# 不能混用

# Load1
lot_number_1, payload_1, process_token_1

# Load2
lot_number_2, payload_2, process_token_2

# 错误组合
verify(
    lot_number=lot_number_1,
    payload=payload_2,  # ❌ 来自Load2
    process_token=process_token_1
)
# 结果：验证失败
```

## ✅ **最佳实践**

### 1. 使用完整的verify方法
```python
# ✅ 推荐：一次性完成所有步骤
result = geetest_helper.verify(challenge=challenge)

# ❌ 不推荐：手动管理各个步骤
load_data = load(...)
answers = recognize(...)
w_param = generate_w(...)
verify_result = verify(...)
```

### 2. 立即使用验证结果
```python
# ✅ 推荐：Verify后立即抢单
geetest_result = verify(challenge)
grab_order(order_id, geetest_result)  # 立即使用

# ❌ 不推荐：延迟使用
geetest_result = verify(challenge)
time.sleep(60)  # 等待60秒
grab_order(order_id, geetest_result)  # 可能已过期
```

### 3. 每次抢单都重新验证
```python
# ✅ 推荐：每个订单独立验证
for order in orders:
    geetest_result = verify(challenge)  # 新的验证码
    grab_order(order, geetest_result)

# ❌ 不推荐：复用验证结果
geetest_result = verify(challenge)  # 一次验证
for order in orders:
    grab_order(order, geetest_result)  # 复用（会失败）
```

## 📊 **数据流图**

```
Load请求
    ↓
生成唯一的lot_number
    ↓
返回：lot_number + imgs + ques + payload + process_token
    ↓
识别：使用这个验证码的imgs和ques
    ↓
生成W：使用这个验证码的lot_number
    ↓
Verify：使用这个验证码的lot_number + payload + process_token + W
    ↓
返回：pass_token + captcha_output（基于这个lot_number）
    ↓
抢单：使用这个验证码的lot_number + pass_token + captcha_output
    ↓
成功！
```

## 🎯 **总结**

1. **lot_number是唯一标识** - 每次Load都不同
2. **数据必须来自同一个Load** - payload、process_token、lot_number必须匹配
3. **W参数必须基于正确的lot_number** - 否则Verify失败
4. **验证结果有时效性** - 需要立即使用
5. **不能复用验证结果** - 每次抢单都要重新验证
6. **APP传递captcha_id最安全** - 让AI服务器保证数据一致性
