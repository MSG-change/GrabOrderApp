#!/bin/bash
# 快速修复并重新构建

echo "========================================"
echo "🔧 修复构建配置"
echo "========================================"
echo ""

cd /Users/duanzubin/develop/script/siam-autolabel/GrabOrderApp

echo "📝 修改已完成："
echo "   buildozer.spec: 设置入口为 main_beautiful.py"
echo ""

echo "📊 当前修改："
git diff buildozer.spec

echo ""
echo "========================================"
read -p "是否提交并推送？(y/n) " -n 1 -r
echo ""
echo "========================================"
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ 取消"
    exit 0
fi

# 提交
git add buildozer.spec

git commit -m "🐛 修复: 使用美化版 UI (main_beautiful.py)

- 修改 buildozer.spec 入口文件
- 从 main.py (旧版) 改为 main_beautiful.py (美化版)
- 修复构建错误的界面问题
"

# 推送
echo "🚀 推送到 GitHub..."
git push origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "========================================"
    echo "✅ 修复完成！"
    echo "========================================"
    echo ""
    echo "🔄 GitHub Actions 将自动重新构建"
    echo ""
    echo "📊 查看新的构建："
    echo "   https://github.com/MSG-change/GrabOrderApp/actions"
    echo ""
    echo "⏱️  预计 10-20 分钟后完成"
    echo "========================================"
else
    echo "❌ 推送失败"
    exit 1
fi

