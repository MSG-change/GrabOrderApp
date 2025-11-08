#!/bin/bash
# 完整检查所有可能的问题

echo "========================================"
echo "🔍 完整性检查"
echo "========================================"
echo ""

cd "$(dirname "$0")"

# 1. 检查入口文件
echo "【1】检查入口文件"
if [ -f "main_beautiful.py" ]; then
    echo "✅ main_beautiful.py 存在"
else
    echo "❌ main_beautiful.py 不存在"
    exit 1
fi

# 2. 检查 buildozer.spec
echo ""
echo "【2】检查 buildozer.spec"
if grep -q "source.entry_point = main_beautiful.py" buildozer.spec; then
    echo "✅ 入口点正确: main_beautiful.py"
else
    echo "❌ 入口点错误"
    exit 1
fi

if grep -q "source.include_patterns = assets/\*,libs/\*,src/\*" buildozer.spec; then
    echo "✅ include_patterns 正确"
else
    echo "⚠️ include_patterns 可能不完整"
fi

# 3. 检查必要的目录和文件
echo ""
echo "【3】检查必要的目录和文件"

dirs=("src" "libs" "assets")
for dir in "${dirs[@]}"; do
    if [ -d "$dir" ]; then
        echo "✅ $dir/ 存在"
    else
        echo "❌ $dir/ 不存在"
        exit 1
    fi
done

# 4. 检查关键 Python 文件
echo ""
echo "【4】检查关键文件"

files=(
    "src/frida_manager.py"
    "src/auto_hook_service.py"
    "src/fast_grab_service.py"
    "libs/geetest_helper_local.py"
    "libs/android_w_generator.py"
)

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file 缺失"
        exit 1
    fi
done

# 5. 检查 ONNX 模型
echo ""
echo "【5】检查 ONNX 模型"
if [ -f "assets/best_siamese_model.onnx" ]; then
    size=$(ls -lh assets/best_siamese_model.onnx | awk '{print $5}')
    echo "✅ ONNX 模型存在 ($size)"
else
    echo "⚠️ ONNX 模型不存在（可选）"
fi

# 6. 检查 Frida Server
echo ""
echo "【6】检查 Frida Server"
if [ -f "assets/frida-server-arm64" ]; then
    size=$(ls -lh assets/frida-server-arm64 | awk '{print $5}')
    echo "✅ Frida Server 存在 ($size)"
elif [ -f "assets/frida-server-arm64.xz" ]; then
    echo "⚠️ Frida Server 是压缩包，GitHub Actions 会自动解压"
else
    echo "⚠️ Frida Server 不存在，GitHub Actions 会自动下载"
fi

# 7. 检查 GitHub Actions
echo ""
echo "【7】检查 GitHub Actions 配置"
if [ -f "../.github/workflows/build-apk.yml" ]; then
    echo "✅ build-apk.yml 存在"
    
    if grep -q "buildozer.spec" ../.github/workflows/build-apk.yml; then
        echo "✅ 使用正确的 buildozer.spec"
    else
        echo "❌ 可能使用了错误的配置文件"
    fi
else
    echo "❌ build-apk.yml 不存在"
    exit 1
fi

# 8. 语法检查
echo ""
echo "【8】Python 语法检查"
python3 -m py_compile main_beautiful.py 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ main_beautiful.py 语法正确"
else
    echo "❌ main_beautiful.py 有语法错误"
    python3 -m py_compile main_beautiful.py
    exit 1
fi

echo ""
echo "========================================"
echo "✅ 所有检查通过！"
echo "========================================"
echo ""
echo "📊 文件统计："
echo "   Python 文件: $(find . -name '*.py' | wc -l)"
echo "   总大小: $(du -sh . | awk '{print $1}')"
echo ""
echo "🚀 可以提交并构建了！"
echo "========================================"

