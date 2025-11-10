#!/bin/bash
# 快速构建APK脚本

echo "🚀 GrabOrderApp APK 快速构建"
echo "======================================"

# 1. 设置Java环境
export JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.15/libexec/openjdk.jdk/Contents/Home
export PATH=$JAVA_HOME/bin:$PATH

# 2. 设置OpenSSL环境
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"

# 3. 创建软链接（如果需要）
if [ ! -L /opt/homebrew/opt/openssl@1.1 ]; then
    ln -sf /opt/homebrew/opt/openssl@3 /opt/homebrew/opt/openssl@1.1 2>/dev/null
fi

echo "✅ 环境配置完成"
echo "   Java: JDK 17"
echo "   OpenSSL: v3"
echo ""

# 4. 构建APK
echo "🔨 开始构建..."
buildozer android debug

# 5. 显示结果
echo ""
if ls bin/*.apk 1> /dev/null 2>&1; then
    echo "✅ 构建成功！"
    echo ""
    echo "📦 生成的APK："
    ls -lh bin/*.apk
    echo ""
    echo "📱 安装命令："
    echo "   adb install -r bin/*.apk"
else
    echo "❌ 构建失败"
    echo "   请查看上面的错误信息"
fi
