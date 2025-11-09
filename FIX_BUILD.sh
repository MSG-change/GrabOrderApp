#!/bin/bash
# 修复 APK 打包依赖问题

echo "🔧 修复 APK 打包依赖"
echo "===================="
echo ""

# 1. 安装 openssl@3（替代已废弃的 openssl@1.1）
echo "1️⃣ 安装 openssl@3..."
brew install openssl@3

# 创建软链接让 buildozer 找到 openssl
echo "   创建 openssl 软链接..."
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"
export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig"

# 2. 安装 JDK 17
echo ""
echo "2️⃣ 安装 JDK 17..."
brew install openjdk@17

# 3. 设置 JAVA_HOME
echo ""
echo "3️⃣ 设置 JAVA_HOME..."
export JAVA_HOME=$(/usr/libexec/java_home -v 17)
echo "JAVA_HOME=$JAVA_HOME"

# 4. 验证
echo ""
echo "4️⃣ 验证环境..."
echo "Java 版本:"
java -version

echo ""
echo "OpenSSL 版本:"
brew list openssl@3 2>/dev/null || echo "OpenSSL 3 未安装"

echo ""
echo "环境变量:"
echo "JAVA_HOME=$JAVA_HOME"
echo "LDFLAGS=$LDFLAGS"
echo "CPPFLAGS=$CPPFLAGS"

echo ""
echo "===================="
echo "✅ 依赖修复完成！"
echo ""
echo "现在可以重新打包："
echo "  buildozer android debug"
echo ""
