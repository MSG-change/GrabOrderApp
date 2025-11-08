#!/bin/bash
# APK 打包脚本 - 纯手机版

echo "========================================"
echo "📦 打包 APK - 纯手机版"
echo "========================================"
echo ""

# 检查 buildozer
if ! command -v buildozer &> /dev/null; then
    echo "❌ buildozer 未安装"
    echo ""
    echo "请先安装 buildozer:"
    echo "  pip install buildozer"
    echo "  pip install cython"
    exit 1
fi

echo "✅ buildozer 已安装"
echo ""

# 检查配置文件
if [ ! -f "buildozer_allinone.spec" ]; then
    echo "❌ 配置文件不存在: buildozer_allinone.spec"
    exit 1
fi

echo "✅ 配置文件存在"
echo ""

# 下载 Frida Server（如果不存在）
echo "📥 检查 Frida Server..."

FRIDA_VERSION="16.1.8"
FRIDA_ARM64="frida-server-${FRIDA_VERSION}-android-arm64"
FRIDA_ARM="frida-server-${FRIDA_VERSION}-android-arm"

if [ ! -f "assets/$FRIDA_ARM64" ] && [ ! -f "assets/$FRIDA_ARM" ]; then
    echo "⚠️  Frida Server 不存在，需要手动下载"
    echo ""
    echo "请执行以下步骤:"
    echo ""
    echo "1. 创建 assets 目录:"
    echo "   mkdir -p assets"
    echo ""
    echo "2. 下载 Frida Server (ARM64):"
    echo "   curl -L -o assets/${FRIDA_ARM64}.xz \\"
    echo "     https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_ARM64}.xz"
    echo ""
    echo "3. 解压:"
    echo "   unxz assets/${FRIDA_ARM64}.xz"
    echo ""
    echo "4. 重命名:"
    echo "   mv assets/$FRIDA_ARM64 assets/frida-server-arm64"
    echo ""
    echo "然后重新运行此脚本"
    echo ""
    exit 1
else
    echo "✅ Frida Server 已存在"
fi

echo ""

# 检查 ONNX 模型
echo "🔍 检查 ONNX 模型..."

if [ ! -f "best_siamese_model.onnx" ]; then
    echo "⚠️  ONNX 模型不存在"
    echo "   请确保 best_siamese_model.onnx 在当前目录"
    echo ""
    read -p "是否继续打包（不包含 AI 识别功能）？[y/N] " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo "✅ ONNX 模型存在"
fi

echo ""

# 清理旧构建
echo "🧹 清理旧构建..."
rm -rf .buildozer bin

echo ""
echo "========================================"
echo "🚀 开始打包..."
echo "========================================"
echo ""

# 使用自定义配置文件
buildozer -v android debug -s buildozer_allinone.spec

if [ $? -eq 0 ]; then
    echo ""
    echo "========================================"
    echo "✅ 打包成功！"
    echo "========================================"
    echo ""
    echo "APK 位置:"
    ls -lh bin/*.apk
    echo ""
    echo "下一步:"
    echo "1. 将 APK 发送到手机"
    echo "2. 在手机上安装"
    echo "3. 给客户使用"
    echo ""
    echo "客户文档: ../客户使用指南.md"
    echo ""
else
    echo ""
    echo "========================================"
    echo "❌ 打包失败"
    echo "========================================"
    echo ""
    echo "常见问题:"
    echo "1. 检查是否安装了所有依赖"
    echo "2. 检查 Android SDK/NDK 是否正确"
    echo "3. 查看上方错误日志"
    echo ""
fi

