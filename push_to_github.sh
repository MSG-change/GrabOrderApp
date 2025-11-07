#!/bin/bash
# 快速推送到GitHub

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║           🚀 推送到 GitHub - 自动构建 APK                          ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# 检查git
if ! command -v git &> /dev/null; then
    echo "❌ Git未安装"
    exit 1
fi

cd "$(dirname "$0")"

# 初始化git（如果需要）
if [ ! -d ".git" ]; then
    echo "📦 初始化Git仓库..."
    git init
    echo "✅ Git仓库初始化完成"
    echo ""
fi

# 添加文件
echo "📝 添加文件..."
git add .
echo "✅ 文件添加完成"
echo ""

# 提交
echo "💾 提交更改..."
git commit -m "Kivy抢单应用 - $(date '+%Y-%m-%d %H:%M:%S')"
echo "✅ 提交完成"
echo ""

# 检查是否已设置remote
if git remote | grep -q "origin"; then
    echo "📤 推送到GitHub..."
    git push
    echo ""
    echo "✅ 推送成功！"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📱 查看构建进度："
    echo "   访问您的GitHub仓库 → Actions 标签"
    echo ""
    echo "⏱️  预计构建时间：30-60分钟"
    echo ""
    echo "📦 构建完成后下载APK："
    echo "   Actions → 点击最新构建 → 底部 Artifacts → 下载"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "⚠️  首次推送，请先设置GitHub仓库"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "第1步：创建GitHub仓库"
    echo "  1. 访问 https://github.com/new"
    echo "  2. 仓库名称：GrabOrderApp"
    echo "  3. 选择：Private（私有）"
    echo "  4. 点击 Create repository"
    echo ""
    echo "第2步：设置远程仓库"
    echo "  执行以下命令（替换为您的用户名）："
    echo ""
    echo "  git remote add origin https://github.com/您的用户名/GrabOrderApp.git"
    echo "  git branch -M main"
    echo "  git push -u origin main"
    echo ""
    echo "第3步：查看构建"
    echo "  推送后，访问GitHub仓库 → Actions 标签"
    echo "  30-60分钟后下载APK"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi

