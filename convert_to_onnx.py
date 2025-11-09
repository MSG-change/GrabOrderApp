#!/usr/bin/env python3
"""
将PyTorch模型转换为ONNX格式
ONNX更适合在Android设备上运行
"""

import torch
import torch.onnx
import os
import sys

# 添加libs到路径
sys.path.append('libs')
from siamese_network import SiameseNetwork

def convert_pytorch_to_onnx():
    """转换PyTorch模型到ONNX格式"""
    
    print("🔄 开始转换 PyTorch -> ONNX...")
    
    # 1. 加载PyTorch模型
    model_path = "best_siamese_model.pth"
    
    if not os.path.exists(model_path):
        print(f"❌ 找不到模型文件: {model_path}")
        return False
    
    # 初始化模型
    model = SiameseNetwork(feature_dim=512)
    
    # 加载权重（PyTorch 2.6+需要设置weights_only=False）
    checkpoint = torch.load(model_path, map_location='cpu', weights_only=False)
    if isinstance(checkpoint, dict) and 'model_state_dict' in checkpoint:
        model.load_state_dict(checkpoint['model_state_dict'])
        accuracy = checkpoint.get('val_acc', 0) * 100
        print(f"   模型准确率: {accuracy:.2f}%")
    else:
        model.load_state_dict(checkpoint)
    
    model.eval()
    
    # 2. 创建示例输入
    batch_size = 1
    dummy_input1 = torch.randn(batch_size, 3, 224, 224)
    dummy_input2 = torch.randn(batch_size, 3, 224, 224)
    
    # 3. 导出ONNX
    onnx_path = "siamese_model.onnx"
    
    print(f"📦 导出到: {onnx_path}")
    
    torch.onnx.export(
        model,                      # 模型
        (dummy_input1, dummy_input2),  # 示例输入
        onnx_path,                  # 输出路径
        export_params=True,         # 导出参数
        opset_version=11,           # ONNX版本
        do_constant_folding=True,   # 优化常量
        input_names=['image1', 'image2'],   # 输入名
        output_names=['similarity', 'distance', 'cosine'],  # 输出名
        dynamic_axes={              # 动态轴（支持不同batch size）
            'image1': {0: 'batch_size'},
            'image2': {0: 'batch_size'},
            'similarity': {0: 'batch_size'}
        }
    )
    
    # 4. 验证ONNX模型
    try:
        import onnx
        onnx_model = onnx.load(onnx_path)
        onnx.checker.check_model(onnx_model)
        print("✅ ONNX模型验证通过")
    except Exception as e:
        print(f"⚠️  ONNX验证失败: {e}")
    
    # 5. 显示模型信息
    file_size = os.path.getsize(onnx_path) / (1024 * 1024)
    print(f"\n📊 模型信息:")
    print(f"   原始大小: {os.path.getsize(model_path) / (1024*1024):.2f} MB")
    print(f"   ONNX大小: {file_size:.2f} MB")
    print(f"   压缩率: {file_size / (os.path.getsize(model_path) / (1024*1024)) * 100:.1f}%")
    
    # 6. 优化ONNX（可选）
    optimize_onnx(onnx_path)
    
    return True


def optimize_onnx(onnx_path):
    """优化ONNX模型用于移动端"""
    try:
        from onnxruntime.quantization import quantize_dynamic, QuantType, QuantFormat
        
        print("\n🔧 优化ONNX模型...")
        
        # 量化模型（减小体积）
        quantized_path = onnx_path.replace('.onnx', '_quantized.onnx')
        
        try:
            quantize_dynamic(
                onnx_path,
                quantized_path,
                weight_type=QuantType.QUInt8  # 8位量化
            )
        except (ValueError, RuntimeError) as e:
            print(f"   ⚠️ 动态量化失败: {e}")
            print(f"   使用简单优化...")
            # 简单复制文件作为备用
            import shutil
            shutil.copy(onnx_path, quantized_path)
            return
        
        # 比较大小
        original_size = os.path.getsize(onnx_path) / (1024 * 1024)
        quantized_size = os.path.getsize(quantized_path) / (1024 * 1024)
        
        print(f"✅ 量化完成:")
        print(f"   原始: {original_size:.2f} MB")
        print(f"   量化: {quantized_size:.2f} MB")
        print(f"   减小: {(1 - quantized_size/original_size) * 100:.1f}%")
        
    except ImportError:
        print("   提示: 安装onnxruntime可以进一步优化模型")
        print("   pip install onnxruntime")


if __name__ == "__main__":
    convert_pytorch_to_onnx()
