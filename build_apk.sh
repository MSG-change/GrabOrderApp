#!/bin/bash
# APK 打包脚本 - 自动设置环境变量

# 设置 JDK 17
export JAVA_HOME=$(/usr/libexec/java_home -v 17 2>/dev/null)
if [ -z "$JAVA_HOME" ]; then
    echo "❌ JDK 17 未安装，请运行: brew install openjdk@17"
    exit 1
fi

# 设置 OpenSSL 3
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"
export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig"

echo "🔧 环境配置"
echo "===================="
echo "JAVA_HOME: $JAVA_HOME"
echo "Java 版本: $($JAVA_HOME/bin/java -version 2>&1 | head -1)"
echo "OpenSSL: $(brew --prefix openssl@3 2>/dev/null || echo '未安装')"
echo "===================="
echo ""

#!/bin/bash
# 打包 Android APK

echo "======================================================================="
echo "🚀 抢单助手 - APK 打包工具"
echo "======================================================================="
echo ""

# 检查 buildozer
if ! command -v buildozer &> /dev/null; then
    echo "❌ buildozer 未安装"
    echo ""
    echo "安装方法："
    echo "  pip install buildozer"
    echo "  pip install cython"
    echo ""
    exit 1
fi

# 检查依赖
echo "📦 检查依赖..."
echo ""

# 询问是否清理（可选）
read -p "是否清理旧的构建文件？(y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -d ".buildozer" ]; then
        echo "🗑️  清理旧的构建文件..."
        rm -rf .buildozer
    fi
    
    if [ -d "bin" ]; then
        echo "🗑️  清理旧的APK..."
        rm -rf bin
    fi
else
    echo "⏭️  跳过清理，使用缓存加速构建"
fi

echo ""
echo "======================================================================="
echo "🔨 开始构建 APK（首次构建可能需要30-60分钟）"
echo "======================================================================="
echo ""

# 构建 APK
buildozer -v android debug

echo ""
echo "======================================================================="
echo "✅ 构建完成！"
echo "======================================================================="
echo ""

if [ -f "bin/*.apk" ]; then
    echo "📦 APK 文件："
    ls -lh bin/*.apk
    echo ""
    echo "安装方法："
    echo "  1. 通过 USB："
    echo "     adb install bin/graborder-1.0.0-arm64-v8a-debug.apk"
    echo ""
    echo "  2. 直接传输到手机安装"
    echo ""
else
    echo "❌ 构建失败，请检查错误信息"
fi

echo "======================================================================="

