#!/bin/bash
# 使用国内镜像源安装依赖

echo "🚀 使用国内镜像源安装依赖..."
echo ""

# 使用清华镜像源
pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple kivy pillow requests

echo ""
echo "✅ 安装完成！"
echo ""
echo "现在可以预览了："
echo "  python3 main.py"

