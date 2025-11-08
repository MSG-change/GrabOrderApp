#!/bin/bash
# 使用conda安装依赖（适用于conda环境）

echo "🚀 使用conda安装依赖..."
echo ""

# 使用conda安装（如果可用）
if command -v conda &> /dev/null; then
    echo "✅ 检测到conda环境"
    conda install -y -c conda-forge kivy pillow requests
    echo ""
    echo "✅ 安装完成！"
    echo ""
    echo "现在可以预览了："
    echo "  python3 main.py"
else
    echo "❌ 未检测到conda，请使用其他安装方法"
    echo ""
    echo "或者手动安装："
    echo "  pip3 install --user kivy pillow requests"
fi

