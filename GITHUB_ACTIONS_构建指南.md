# 🚀 GitHub Actions 自动构建 APK

## ✅ 优势

- 🆓 **完全免费**（GitHub提供2000分钟/月免费额度）
- 🌏 **无网络限制**（GitHub服务器在国外）
- ⚡ **自动化构建**（推送代码自动触发）
- 📦 **自动保存APK**（构建完成自动上传）

---

## 📋 操作步骤

### 第1步：初始化Git仓库

```bash
cd /Users/duanzubin/develop/script/siam-autolabel/GrabOrderApp

# 初始化git（如果还没有）
git init

# 添加所有文件
git add .

# 提交
git commit -m "Initial commit: Kivy抢单应用"
```

### 第2步：创建GitHub仓库

1. 访问 https://github.com/new
2. 仓库名称：`GrabOrderApp`
3. 选择：**Private**（私有仓库，保护您的代码）
4. 不要勾选任何初始化选项
5. 点击 **Create repository**

### 第3步：推送代码

```bash
# 复制GitHub给的命令，类似：
git remote add origin https://github.com/MSG-change/GrabOrderApp.git
git branch -M main
git push -u origin main
```

### 第4步：触发构建

推送完成后：
1. 访问您的GitHub仓库
2. 点击顶部的 **Actions** 标签
3. 您会看到构建正在进行中

### 第5步：下载APK

构建完成后（30-60分钟）：
1. 在 **Actions** 页面点击最新的构建
2. 滚动到底部找到 **Artifacts**
3. 点击 **graborder-apk** 下载
4. 解压得到 `.apk` 文件

---

## ⏱️ 构建时间

- **首次构建**：45-60分钟（下载Android SDK/NDK）
- **后续构建**：20-30分钟（有缓存）

---

## 🔍 查看构建进度

1. GitHub仓库 → **Actions** 标签
2. 点击最新的工作流运行
3. 点击 **build** 查看详细日志
4. 实时查看构建进度

---

## 🎯 手动触发构建

如果您修改了代码，想重新构建：

**方法1：推送代码**
```bash
git add .
git commit -m "Update"
git push
```

**方法2：手动触发**
1. GitHub → Actions
2. 左侧选择 **Build Android APK**
3. 点击 **Run workflow**
4. 点击绿色的 **Run workflow** 按钮

---

## 📱 安装APK到手机

### USB安装
```bash
adb install graborder-*.apk
```

### 直接安装
1. 下载APK到手机
2. 点击安装
3. 如果提示"未知来源"，需要在设置中允许

---

## 🔒 隐私保护

- ✅ 使用**私有仓库**（Private）
- ✅ 代码只有您能看到
- ✅ APK只有您能下载
- ✅ GitHub Actions构建日志也是私有的

---

## 💡 常见问题

### Q: 构建失败了怎么办？

A: 查看Actions日志，找到错误信息。通常是依赖问题，可以修改 `buildozer.spec`。

### Q: 免费额度够用吗？

A: GitHub提供2000分钟/月免费额度，构建一次约1小时，够用20次以上。

### Q: 可以构建发布版吗？

A: 可以，修改 `.github/workflows/build-apk.yml`，把 `buildozer android debug` 改为 `buildozer android release`。

---

## 🎉 完成！

推送代码后，GitHub会自动开始构建，30-60分钟后下载APK即可！

