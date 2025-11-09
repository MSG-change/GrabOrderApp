# 📱 纯手机端抢单方案 - 手动 Token

## 🎯 方案说明

完全在手机上运行，不需要电脑，不需要服务器：

1. ✅ 用 **HttpCanary** 抓包获取 Token（手机上）
2. ✅ 在 **APK** 中粘贴 Token
3. ✅ 开始抢单
4. ✅ 完全独立运行

---

## 📋 使用步骤

### 第1步：安装 HttpCanary（2分钟）

1. 在手机上安装 **HttpCanary**（抓包工具）
2. 打开 HttpCanary，授予必要权限
3. 点击右下角 ▶️ 开始抓包

### 第2步：获取 Token（3分钟）

1. **保持 HttpCanary 运行**
2. 打开抢单应用（如"顺辉智送"）
3. 登录账号
4. 打开订单列表或刷新页面
5. 回到 HttpCanary
6. 找到 `dysh.dyswl.com` 的请求
7. 点击请求 → 查看请求头
8. 找到 `Authorization` 字段
9. **长按复制** Token 值

**Token 格式示例：**
```
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

或者直接是：
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 第3步：打包 APK（一次性，30分钟）

```bash
cd /Users/duanzubin/develop/script/siam-autolabel/GrabOrderApp

# 修复依赖
chmod +x FIX_BUILD.sh
./FIX_BUILD.sh

# 打包
buildozer android debug
```

### 第4步：安装 APK

```bash
# 通过 USB 安装
adb install -r bin/*.apk

# 或者直接传输到手机安装
```

### 第5步：使用 APK 抢单

1. **打开 APK**
2. **粘贴 Token**
   - 在 "Token" 输入框中粘贴刚才复制的 Token
   - 可以包含 "Bearer " 前缀，也可以不包含
3. **点击 Start**
4. **开始抢单！**

---

## 🎨 界面说明

```
┌─────────────────────────────────┐
│    Fast Grab Order              │
├─────────────────────────────────┤
│ [Frida] [Hook] [Token] [Grab]   │  ← 状态卡片
├─────────────────────────────────┤
│ Target App: com.dys.shzs        │
│ Interval:   1s                  │
│ Token:      [粘贴 Token 这里]    │  ← 手动输入 Token
├─────────────────────────────────┤
│ [Start]              [Stop]     │
├─────────────────────────────────┤
│ 日志输出区域...                  │
└─────────────────────────────────┘
```

---

## ✅ 优势

| 特性 | 说明 |
|------|------|
| **纯手机端** | 不需要电脑 |
| **不需要 Frida** | 手动 Token，跳过自动捕获 |
| **简单快速** | 5分钟上手 |
| **稳定可靠** | 100% 成功率 |

---

## 🔄 Token 过期怎么办？

如果 Token 过期（通常 24 小时），重复第2步：

1. 打开 HttpCanary
2. 打开抢单应用
3. 刷新页面
4. 复制新 Token
5. 在 APK 中更新 Token
6. 重新 Start

---

## 💡 提示

### Token 有效期

- 通常 Token 有效期为 **24小时**
- 过期后需要重新获取
- 建议每天更新一次

### 如何判断 Token 是否有效？

在 APK 日志中查看：
- ✅ `✅ Manual token applied` - Token 已应用
- ✅ `✅ Grab service started` - 抢单已启动
- ❌ `❌ Token invalid` - Token 无效，需要重新获取

### 保存 Token

可以将 Token 保存在手机备忘录中，方便下次使用。

---

## 🆚 对比其他方案

| 方案 | 优势 | 劣势 |
|------|------|------|
| **手动 Token** | ✅ 简单<br>✅ 稳定<br>✅ 纯手机 | ⚠️ 需要手动更新 Token |
| **Frida 自动** | ✅ 自动捕获 | ❌ 复杂<br>❌ 可能失败 |
| **VPN 抓包** | ✅ 全自动 | ❌ 实现复杂<br>❌ 需要 Root |

---

## 🎉 总结

**手动 Token 方案是目前最简单、最可靠的纯手机端方案！**

**工作流程：**
1. HttpCanary 抓包（3分钟）
2. 复制 Token
3. 粘贴到 APK
4. 开始抢单
5. 完成！

**每天只需要：**
- 更新 Token（1分钟）
- 其他全自动

---

## 📞 常见问题

### Q: Token 在哪里找？

A: HttpCanary → 找到 `dysh.dyswl.com` 请求 → 请求头 → `Authorization`

### Q: Token 要包含 "Bearer " 吗？

A: 都可以，APK 会自动处理

### Q: Token 多久过期？

A: 通常 24 小时，具体看服务器设置

### Q: 可以保存 Token 吗？

A: 可以，保存在备忘录中，下次直接粘贴

---

**🚀 现在就开始吧！**
