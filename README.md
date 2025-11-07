# 🚀 抢单助手 - Android 应用

基于 **Python + Kivy** 开发的自动抢单 Android 应用

## ✨ 核心功能

### 1. 🔒 VPN 本地抓包
- ✅ 自动捕获网络请求
- ✅ 实时提取 Authorization Token
- ✅ 自动更新 club-id、role-id、tenant-id
- ✅ **无需 Root 权限**

### 2. 🎯 智能抢单
- ✅ 实时监控订单池
- ✅ 自动抢单
- ✅ Geetest 验证码自动识别
- ✅ 可配置检查间隔

### 3. 💡 用户友好
- ✅ 悬浮窗控制（开始/停止）
- ✅ 实时日志显示
- ✅ Token 状态监控
- ✅ 后台运行

---

## 📦 项目结构

```
GrabOrderApp/
├── main.py                 # 主程序入口
├── src/
│   ├── vpn_service.py      # VPN 抓包服务
│   ├── grab_service.py     # 抢单业务逻辑
│   └── config_manager.py   # 配置管理
├── libs/                   # Python 库
│   ├── geetest_helper_local.py
│   ├── local_w_generator.py
│   └── siamese_network.py
├── assets/                 # 资源文件
│   ├── best_siamese_model.pth
│   └── jiyanv4/            # W 参数生成 JS
├── buildozer.spec          # APK 打包配置
└── build_apk.sh            # 打包脚本
```

---

## 🔧 环境准备

### 1. 安装依赖（Ubuntu/Debian）

```bash
# 系统依赖
sudo apt update
sudo apt install -y python3 python3-pip git zip unzip openjdk-11-jdk

# Android SDK 依赖
sudo apt install -y autoconf automake libtool pkg-config \
    zlib1g-dev libncurses5-dev libffi-dev libssl-dev

# Python 依赖
pip3 install buildozer cython
```

### 2. 安装依赖（macOS）

```bash
# 安装 Homebrew（如果未安装）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 系统依赖
brew install python3 git zip unzip openjdk@11

# Python 依赖
pip3 install buildozer cython
```

---

## 🚀 构建 APK

### 方式 1: 一键构建

```bash
cd GrabOrderApp
./build_apk.sh
```

### 方式 2: 手动构建

```bash
cd GrabOrderApp

# 调试版本（快速）
buildozer android debug

# 发布版本（优化）
buildozer android release
```

### 构建时间

- **首次构建**: 30-60 分钟（下载 Android SDK、NDK）
- **后续构建**: 5-10 分钟

---

## 📱 安装到手机

### 方式 1: USB 安装

```bash
# 连接手机，启用 USB 调试
adb install bin/graborder-1.0.0-arm64-v8a-debug.apk
```

### 方式 2: 直接传输

1. 将 `bin/` 目录下的 `.apk` 文件传输到手机
2. 在手机上点击安装

---

## 🎮 使用方法

### 第一次启动

1. **安装并打开应用**

2. **授予权限**
   - VPN 权限（用于抓包）
   - 网络权限
   - 存储权限
   - 悬浮窗权限（可选）

3. **启用 VPN 抓包**
   - 打开应用
   - 确保 "自动获取Token" 开关已启用

4. **打开抢单应用登录**
   - 打开你的抢单目标应用（如 "顺辉智送"）
   - 正常登录
   - **VPN 会自动捕获 Token！**

5. **启动抢单**
   - 返回抢单助手
   - 点击 "启动抢单"
   - 查看日志确认运行状态

### 日常使用

1. 打开应用
2. 点击 "启动抢单"
3. 最小化到后台（应用会继续运行）
4. 查看通知栏确认运行状态

---

## ⚙️ 配置说明

配置文件：`/sdcard/Android/data/com.graborder/files/config.json`

```json
{
  "phone": "18113011654",
  "api_base_url": "https://dysh.dyswl.com",
  "category_id": "2469",
  "check_interval": 2,
  "token": "",
  "club_id": "",
  "role_id": "",
  "tenant_id": ""
}
```

### 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `phone` | 手机号 | `18113011654` |
| `api_base_url` | API 地址 | `https://dysh.dyswl.com` |
| `category_id` | 产品分类 ID | `2469` |
| `check_interval` | 检查间隔（秒） | `2` |
| `token` | 认证 Token | 自动获取 |
| `club_id` | 俱乐部 ID | 自动获取 |
| `role_id` | 角色 ID | 自动获取 |
| `tenant_id` | 租户 ID | 自动获取 |

---

## 🔍 VPN 抓包原理

### 工作流程

```
┌─────────────┐
│  抢单应用    │
│ (目标 App)   │
└──────┬──────┘
       │ HTTP/HTTPS 请求
       ↓
┌──────────────┐
│ 本地 VPN      │
│ (抓包层)      │ → 提取 Token、Headers
└──────┬───────┘
       │ 转发请求
       ↓
┌──────────────┐
│  服务器       │
└──────────────┘
```

### 安全性

- ✅ 仅在本地抓包，不上传数据
- ✅ 仅解析目标域名（dysh.dyswl.com）
- ✅ Token 存储在本地配置文件
- ✅ 开源透明，可审计

---

## 📊 性能优化

### 1. 降低检查间隔

```json
{
  "check_interval": 1  // 从 2 秒降至 1 秒
}
```

### 2. 后台运行优化

- 在设置中允许应用后台运行
- 在电池优化中排除此应用

### 3. 网络优化

- 使用 4G/5G 网络（比 WiFi 延迟低）
- 关闭省电模式

---

## 🐛 常见问题

### 1. VPN 连接失败

**问题**: 点击 "启动抢单" 后提示 VPN 连接失败

**解决**:
- 检查是否授予了 VPN 权限
- 尝试重启应用
- 检查是否有其他 VPN 应用冲突

### 2. Token 未捕获

**问题**: 日志显示 "未获取 Token"

**解决**:
1. 确保 "自动获取Token" 开关已启用
2. 打开目标抢单应用并登录
3. 查看日志是否有 "🎯 捕获到Token" 提示

### 3. Geetest 验证失败

**问题**: 抢单时提示 "Geetest验证失败"

**解决**:
- 检查网络连接
- 确保模型文件 `best_siamese_model.pth` 存在
- 查看日志中的识别结果是否正确

### 4. 抢单失败

**问题**: 日志显示 "抢单失败"

**原因**:
- Token 已过期 → VPN 会自动捕获新 Token
- 订单已被抢 → 正常现象
- 权限不足 → 检查 role-id、club-id

---

## 🔐 权限说明

| 权限 | 用途 | 是否必需 |
|------|------|---------|
| `INTERNET` | 网络请求 | ✅ 必需 |
| `ACCESS_NETWORK_STATE` | 检查网络状态 | ✅ 必需 |
| `BIND_VPN_SERVICE` | VPN 抓包 | ✅ 必需 |
| `WRITE_EXTERNAL_STORAGE` | 保存配置 | ✅ 必需 |
| `SYSTEM_ALERT_WINDOW` | 悬浮窗 | 可选 |
| `FOREGROUND_SERVICE` | 后台运行 | 推荐 |

---

## 🛠️ 开发调试

### PC 端测试

```bash
# 安装 Kivy
pip install kivy

# 运行应用（PC 模式）
python main.py
```

**注意**: PC 模式下 VPN 抓包功能不可用，但可以测试 UI 和抢单逻辑。

### 查看日志

```bash
# 实时查看 Android 日志
adb logcat -s python
```

### 重新构建

```bash
# 清理缓存
buildozer android clean

# 重新构建
buildozer android debug
```

---

## 📈 后续优化

### 计划功能

- [ ] 悬浮窗快捷控制
- [ ] 抢单成功通知
- [ ] 多账号支持
- [ ] 订单筛选规则
- [ ] 统计分析面板

### 性能优化

- [ ] 使用 ONNX Runtime 加速模型推理
- [ ] HTTP/2 支持
- [ ] 请求池复用

---

## ⚖️ 免责声明

本应用仅供学习交流使用，请遵守相关法律法规和平台规则。

---

## 📞 技术支持

如有问题，请检查：

1. 日志输出（应用内查看）
2. Android logcat（`adb logcat -s python`）
3. 配置文件（`config.json`）

---

**🎉 祝您抢单成功！**

