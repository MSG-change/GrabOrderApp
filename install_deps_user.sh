#!/bin/bash
# 使用用户目录安装依赖（避免权限问题）

echo "🚀 安装依赖到用户目录..."
echo ""

# 使用 --user 参数安装到用户目录
pip3 install --user kivy pillow requests

echo ""
echo "✅ 安装完成！"
echo ""
echo "现在可以预览了："
echo "  python3 main.py"
echo ""
echo "如果遇到 'kivy: command not found'，可能需要："
echo "  export PATH=\$PATH:\$HOME/Library/Python/3.9/bin"

