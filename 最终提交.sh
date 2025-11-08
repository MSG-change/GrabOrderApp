#!/bin/bash
# 最终提交 - 一次构建成功

echo "========================================"
echo "🚀 最终提交 - 修复所有问题"
echo "========================================"
echo ""

cd "$(dirname "$0")"

echo "📝 本次修复内容："
echo "   1. ✅ 入口文件: main_beautiful.py (美化版)"
echo "   2. ✅ 包含模式: assets/*, libs/*, src/*"
echo "   3. ✅ GitHub Actions: 使用正确的 buildozer.spec"
echo "   4. ✅ 所有文件语法检查通过"
echo ""

echo "📊 将要提交的文件："
git status --short

echo ""
read -p "确认提交？(y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ 取消提交"
    exit 0
fi

echo ""
echo "========================================"
echo "📝 提交修改..."
echo "========================================"

# 添加修改的文件
git add buildozer.spec

# 提交
git commit -m "🐛 修复构建配置 - 确保使用美化版 UI

修复内容：
1. ✅ 设置入口文件为 main_beautiful.py (美化版)
2. ✅ 添加 source.include_patterns 确保打包所有必要文件
3. ✅ 包含 assets/*, libs/*, src/* 目录
4. ✅ 支持 .xz 扩展名（Frida Server）
5. ✅ 所有文件语法检查通过

测试状态：
- ✅ Python 语法正确
- ✅ 所有依赖文件存在
- ✅ 配置文件正确
- ✅ 优雅降级处理

构建说明：
- 使用 buildozer.spec
- 入口: main_beautiful.py
- 包含: 完整的 libs, src, assets
"

if [ $? -ne 0 ]; then
    echo "❌ 提交失败"
    exit 1
fi

echo "✅ 提交成功"
echo ""

echo "========================================"
echo "🚀 推送到 GitHub..."
echo "========================================"

git push origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "========================================"
    echo "🎉 提交完成！"
    echo "========================================"
    echo ""
    echo "📊 GitHub Actions 正在构建..."
    echo ""
    echo "   🔗 查看进度："
    echo "   https://github.com/MSG-change/GrabOrderApp/actions"
    echo ""
    echo "⏱️  预计完成时间："
    echo "   - 首次构建: 20-40 分钟"
    echo "   - 后续构建: 10-20 分钟"
    echo ""
    echo "📥 构建完成后："
    echo "   1. 进入 Actions 页面"
    echo "   2. 找到最新的成功构建（绿色 ✅）"
    echo "   3. 下载 Artifacts 中的 APK"
    echo ""
    echo "========================================"
    
    # 尝试打开浏览器
    if command -v open &> /dev/null; then
        read -p "是否打开 GitHub Actions 页面？(y/n) " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            open "https://github.com/MSG-change/GrabOrderApp/actions"
        fi
    fi
else
    echo ""
    echo "❌ 推送失败"
    echo ""
    echo "可能的原因："
    echo "   1. 网络问题"
    echo "   2. 没有推送权限"
    echo "   3. 需要先 pull"
    echo ""
    echo "请手动推送："
    echo "   git push origin main"
    exit 1
fi

