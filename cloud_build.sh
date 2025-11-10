#!/bin/bash
# 云服务器构建脚本（Ubuntu/Debian）

echo "☁️ 云服务器构建完整版APK"
echo "================================"
echo ""
echo "推荐使用："
echo "1. GitHub Codespaces（免费120小时/月）"
echo "2. Gitpod（免费50小时/月）"
echo "3. 阿里云/腾讯云（按需付费）"
echo ""

# 安装依赖
echo "📦 安装构建环境..."
sudo apt update
sudo apt install -y python3 python3-pip git zip unzip openjdk-17-jdk

# 安装buildozer
pip3 install --user buildozer cython

# 克隆项目
echo "📥 克隆项目..."
git clone https://github.com/MSG-change/GrabOrderApp.git
cd GrabOrderApp

# 下载ONNX模型
echo "📥 下载ONNX模型..."
wget https://github.com/MSG-change/GrabOrderApp/releases/download/v1.7.3-onnx/siamese_model.onnx

# 创建完整版配置
cat > buildozer.spec << 'EOF'
[app]
title = Grab Order Assistant
package.name = graborder
package.domain = com.graborder
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json,js,ttf,onnx
version = 1.7.5-ai

# 包含ONNX Runtime（预编译wheel）
requirements = python3,kivy==2.3.0,pillow,requests,pyjnius,android,numpy,onnxruntime-mobile==1.16.0

[buildozer]
log_level = 2
EOF

# 构建APK
echo "🔨 开始构建APK（包含AI功能）..."
buildozer android debug

echo "✅ 构建完成！"
echo "📱 下载APK: bin/*.apk"
