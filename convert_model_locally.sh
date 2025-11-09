#!/bin/bash
# 本地转换PyTorch模型为ONNX格式
# 只需要运行一次

echo "🔄 转换PyTorch模型为ONNX格式..."

# 1. 安装必要的包（如果没有）
pip install torch torchvision onnx onnxruntime

# 2. 运行转换脚本
python convert_to_onnx.py

# 3. 检查结果
if [ -f "siamese_model.onnx" ]; then
    echo "✅ ONNX模型创建成功"
    ls -lh siamese_model*.onnx
    
    # 4. 上传到Release（可选）
    echo ""
    echo "📤 是否上传到GitHub Release？(y/n)"
    read -r answer
    if [ "$answer" = "y" ]; then
        python upload_model_python.py
    fi
else
    echo "❌ 转换失败"
    exit 1
fi

echo ""
echo "✅ 完成！现在可以使用ONNX模型了"
echo "   - siamese_model.onnx: 完整模型"
echo "   - siamese_model_quantized.onnx: 量化模型（更小）"
