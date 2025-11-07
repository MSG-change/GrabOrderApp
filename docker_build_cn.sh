#!/bin/bash
# Docker构建APK - 使用国内镜像

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║           🐳 Docker 构建 (国内镜像加速版)                          ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

echo "🇨🇳 使用阿里云镜像源..."
echo ""

# 方案A: 尝试使用已有的buildozer镜像（如果存在）
if docker images | grep -q "kivy/buildozer"; then
    echo "✅ 发现本地镜像，直接使用"
    docker run --rm -e BUILDOZER_WARN_ON_ROOT=0 -v "$(pwd)":/app -w /app kivy/buildozer:latest buildozer android debug
    exit $?
fi

echo "========================================================================"
echo "⚠️  需要先下载Docker镜像"
echo "========================================================================"
echo ""
echo "由于网络问题，我们使用以下方案："
echo ""
echo "方案1: 手动配置Docker镜像加速（推荐）"
echo "  1. Docker Desktop → Settings → Docker Engine"
echo "  2. 添加以下配置："
echo ""
echo '  {
    "registry-mirrors": [
      "https://docker.mirrors.sjtug.sjtu.edu.cn",
      "https://docker.nju.edu.cn"
    ]
  }'
echo ""
echo "  3. Apply & Restart"
echo "  4. 再次运行此脚本"
echo ""
echo "方案2: 使用VPN/代理"
echo "  Docker Desktop → Settings → Resources → Proxies"
echo ""
echo "========================================================================"
echo ""

read -p "已配置镜像加速？按回车继续构建，Ctrl+C取消: "

echo ""
echo "🔄 尝试下载镜像..."
docker pull kivy/buildozer:latest

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ 镜像下载成功，开始构建..."
    echo ""
    docker run --rm -e BUILDOZER_WARN_ON_ROOT=0 -v "$(pwd)":/app -w /app kivy/buildozer:latest buildozer android debug
else
    echo ""
    echo "❌ 镜像下载失败"
    echo ""
    echo "💡 建议："
    echo "  1. 检查网络连接"
    echo "  2. 启用VPN/代理"
    echo "  3. 或使用Linux服务器构建（tar -czf打包项目传输）"
fi

