# 📦 GitHub Releases 模型文件托管指南

## 🎯 概述

由于 Siamese 模型文件 (137MB) 太大无法直接提交到 Git 仓库，我们使用 GitHub Releases 来托管。

## 📤 上传模型到 Release

### 方法1: 使用脚本上传（推荐）

```bash
# 1. 确保模型文件存在
ls -lh best_siamese_model.pth

# 2. 安装 GitHub CLI（如果没有）
brew install gh  # macOS
# 或访问 https://cli.github.com 获取其他平台安装方法

# 3. 登录 GitHub CLI
gh auth login

# 4. 运行上传脚本
chmod +x upload_model_to_release.sh
./upload_model_to_release.sh
```

### 方法2: 手动上传

1. 访问 [Releases 页面](https://github.com/MSG-change/GrabOrderApp/releases)
2. 点击 "Draft a new release"
3. 填写信息：
   - Tag version: `v1.7.2`
   - Release title: `Model Files for v1.7.2`
   - 上传文件: `best_siamese_model.pth`
4. 点击 "Publish release"

## 📥 下载模型文件

### 自动下载（推荐）

```bash
# 运行下载脚本
python download_model.py
```

脚本会自动从以下源尝试下载：
1. GitHub 官方地址
2. ghproxy 镜像（国内加速）
3. FastGit 镜像（备用）

### 手动下载

1. 访问: https://github.com/MSG-change/GrabOrderApp/releases/tag/v1.7.2
2. 下载: `best_siamese_model.pth`
3. 放置到 GrabOrderApp 根目录

### 直接下载链接

```
https://github.com/MSG-change/GrabOrderApp/releases/download/v1.7.2/best_siamese_model.pth
```

国内镜像：
```
https://ghproxy.com/https://github.com/MSG-change/GrabOrderApp/releases/download/v1.7.2/best_siamese_model.pth
```

## 🔧 构建 APK

### 本地构建

```bash
# 1. 下载模型
python download_model.py

# 2. 构建 APK
buildozer android debug
```

### GitHub Actions 自动构建

推送代码到 main 分支或创建 tag 后会自动：
1. 从 Release 下载模型文件
2. 构建 APK
3. 上传构建产物

## 📊 模型信息

| 属性 | 值 |
|------|-----|
| 文件名 | best_siamese_model.pth |
| 大小 | 137.44 MB (144,114,997 bytes) |
| 准确率 | 98.88% |
| 用途 | 九宫格图片识别 |

## 🚀 版本管理

更新模型时：
1. 修改 `download_model.py` 中的 `VERSION`
2. 创建新的 Release
3. 上传新模型文件
4. 更新版本号

## ⚠️ 注意事项

1. **文件大小**: 模型文件会增加 APK 大小约 137MB
2. **下载时间**: 首次下载可能需要几分钟
3. **网络要求**: 国内用户建议使用镜像地址
4. **存储空间**: 确保有足够空间存储模型文件

## 🆘 故障排除

### 下载失败

1. 检查网络连接
2. 尝试使用镜像地址
3. 手动从 Release 页面下载

### 模型加载失败

1. 确认文件大小: 144,114,997 bytes
2. 重新下载模型文件
3. 检查文件权限

### APK 构建失败

1. 确保模型文件在根目录
2. 检查 buildozer.spec 配置
3. 查看构建日志

## 📝 更新日志

- **v1.7.2**: 首次发布模型到 GitHub Releases
- 支持多镜像下载
- 添加自动构建流程
