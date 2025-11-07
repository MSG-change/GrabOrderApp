#!/bin/bash
# Docker构建APK脚本

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║           🐳 Docker 构建 Android APK                               ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# 检查Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker未安装"
    echo ""
    echo "请先安装Docker Desktop for Mac:"
    echo "  https://www.docker.com/products/docker-desktop"
    exit 1
fi

# 检查Docker是否运行
if ! docker info &> /dev/null; then
    echo "❌ Docker未运行"
    echo ""
    echo "请先启动Docker Desktop"
    exit 1
fi

echo "✅ Docker检查通过"
echo ""

# 显示项目信息
echo "========================================================================"
echo "📂 项目目录: $(pwd)"
echo "📦 应用名称: 抢单助手 (GrabOrder)"
echo "🏷️  版本: 1.0.0"
echo "========================================================================"
echo ""

# 清理旧文件（可选）
read -p "🗑️  是否清理旧的构建文件？(y/N): " clean
if [[ "$clean" == "y" || "$clean" == "Y" ]]; then
    echo "🗑️  清理中..."
    rm -rf .buildozer bin
    echo "✅ 清理完成"
fi
echo ""

echo "========================================================================"
echo "🔨 开始构建（首次需要30-60分钟，后续5-10分钟）"
echo "========================================================================"
echo ""

# 使用Kivy官方Docker镜像构建
docker run --rm \
    -e BUILDOZER_WARN_ON_ROOT=0 \
    -v "$(pwd)":/app \
    -w /app \
    kivy/buildozer:latest \
    buildozer android debug

# 检查构建结果
if [ $? -eq 0 ]; then
    echo ""
    echo "========================================================================"
    echo "✅ 构建成功！"
    echo "========================================================================"
    echo ""
    
    if [ -d "bin" ]; then
        echo "📦 APK文件:"
        ls -lh bin/*.apk 2>/dev/null || echo "  未找到APK文件"
        echo ""
        echo "安装方法:"
        echo "  1. USB安装: adb install bin/*.apk"
        echo "  2. 传输到手机直接安装"
        echo ""
    fi
else
    echo ""
    echo "========================================================================"
    echo "❌ 构建失败"
    echo "========================================================================"
    echo ""
    echo "常见问题:"
    echo "  1. Docker内存不足 → Docker Desktop → Settings → Resources → 增加内存"
    echo "  2. 网络问题 → 使用VPN或代理"
    echo "  3. 磁盘空间不足 → 清理Docker缓存: docker system prune"
    echo ""
fi

echo "========================================================================"

