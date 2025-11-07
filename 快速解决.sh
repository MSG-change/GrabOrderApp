#!/bin/bash
# 快速解决Docker镜像下载问题

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║           🚀 快速配置 + 构建                                       ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

echo "📋 请按以下步骤操作："
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "第1步：配置Docker镜像加速（必须！）"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. 打开 Docker Desktop"
echo "2. 点击右上角 ⚙️  Settings"
echo "3. 左侧选择 'Docker Engine'"
echo "4. 在右侧JSON配置中，找到或添加 'registry-mirrors' 部分："
echo ""
echo '   {
     "registry-mirrors": [
       "https://docker.mirrors.sjtug.sjtu.edu.cn",
       "https://docker.nju.edu.cn",
       "https://mirror.baidubce.com"
     ]
   }'
echo ""
echo "5. 点击 'Apply & Restart'"
echo "6. 等待Docker重启完成（顶部图标变绿）"
echo ""
read -p "✅ 已完成配置？按回车继续..."
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "第2步：验证配置"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
docker info | grep -A 5 "Registry Mirrors" || echo "⚠️  未检测到镜像配置，请重新配置"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "第3步：下载构建镜像"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔄 正在下载 kivy/buildozer 镜像（约2GB，首次需要5-10分钟）..."
echo ""

docker pull kivy/buildozer:latest

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ 镜像下载成功！"
    echo ""
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "第4步：开始构建APK"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "🔨 开始构建（首次30-60分钟）..."
    echo ""
    
    cd "$(dirname "$0")"
    docker run --rm \
        -e BUILDOZER_WARN_ON_ROOT=0 \
        -v "$(pwd)":/app \
        -w /app \
        kivy/buildozer:latest \
        buildozer android debug
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "╔════════════════════════════════════════════════════════════════════╗"
        echo "║                    ✅ 构建成功！                                   ║"
        echo "╚════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "📦 APK文件位置："
        ls -lh bin/*.apk 2>/dev/null
        echo ""
        echo "安装方法："
        echo "  adb install bin/*.apk"
        echo ""
    else
        echo ""
        echo "❌ 构建失败，请查看错误信息"
    fi
else
    echo ""
    echo "❌ 镜像下载失败"
    echo ""
    echo "💡 可能的原因："
    echo "  1. 镜像源配置未生效 → 请重启Docker Desktop"
    echo "  2. 网络问题 → 尝试启用VPN"
    echo "  3. Docker磁盘空间不足 → docker system prune"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "替代方案：使用Termux"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "您的Termux方案功能完全相同，无需APK！"
    echo ""
    echo "立即运行："
    echo "  cd /Users/duanzubin/develop/script/siam-autolabel"
    echo "  python auto_grab_with_token_manager.py"
    echo ""
fi

