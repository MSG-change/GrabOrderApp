#!/bin/bash
# 使用国内镜像源安装依赖

echo "🚀 使用国内镜像源安装依赖..."
echo ""

# 使用清华镜像源，安装到用户目录（避免权限问题）
pip3 install --user -i https://pypi.tuna.tsinghua.edu.cn/simple kivy pillow requests

echo ""
echo "✅ 安装完成！"
echo ""
echo "现在可以预览了："
echo "  python3 main.py"
echo ""
echo "如果遇到 'kivy: command not found'，可能需要："
echo "  export PATH=\$PATH:\$HOME/Library/Python/3.9/bin"

