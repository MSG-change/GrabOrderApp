#!/usr/bin/env python3
"""
ONNX Runtime推理 - 适合Android运行
轻量级，无需PyTorch
"""

import numpy as np
from PIL import Image
import os
import json

try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False
    print("⚠️  ONNX Runtime未安装，使用备用方案")


class ONNXInference:
    """ONNX模型推理器（Android优化）"""
    
    def __init__(self, model_path="siamese_model_quantized.onnx"):
        """
        初始化ONNX推理器
        
        Args:
            model_path: ONNX模型路径（建议使用量化版本）
        """
        self.model_path = model_path
        self.session = None
        self.input_names = None
        self.output_names = None
        self.threshold = 0.5
        
        if ONNX_AVAILABLE:
            self._load_model()
        else:
            print("📌 使用固定模式（无ONNX）")
    
    def _load_model(self):
        """加载ONNX模型"""
        if not os.path.exists(self.model_path):
            print(f"⚠️  找不到ONNX模型: {self.model_path}")
            return
        
        try:
            # 创建推理会话（优化选项）
            options = ort.SessionOptions()
            options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            
            # Android优化：使用CPU提供器
            providers = ['CPUExecutionProvider']
            
            self.session = ort.InferenceSession(
                self.model_path,
                sess_options=options,
                providers=providers
            )
            
            # 获取输入输出信息
            self.input_names = [inp.name for inp in self.session.get_inputs()]
            self.output_names = [out.name for out in self.session.get_outputs()]
            
            print(f"✅ ONNX模型加载成功")
            print(f"   输入: {self.input_names}")
            print(f"   输出: {self.output_names}")
            
            # 显示模型大小
            model_size = os.path.getsize(self.model_path) / (1024 * 1024)
            print(f"   大小: {model_size:.2f} MB")
            
        except Exception as e:
            print(f"❌ ONNX加载失败: {e}")
            self.session = None
    
    def preprocess_image(self, image):
        """
        预处理图片（与PyTorch保持一致）
        
        Args:
            image: PIL Image或numpy array
        
        Returns:
            预处理后的numpy array
        """
        if isinstance(image, str):
            image = Image.open(image).convert('RGB')
        
        # 调整大小
        image = image.resize((224, 224), Image.Resampling.LANCZOS)
        
        # 转换为numpy数组
        img_array = np.array(image).astype(np.float32)
        
        # 归一化（ImageNet标准）
        mean = np.array([0.485, 0.456, 0.406]) * 255
        std = np.array([0.229, 0.224, 0.225]) * 255
        img_array = (img_array - mean) / std
        
        # 转换维度: HWC -> CHW
        img_array = np.transpose(img_array, (2, 0, 1))
        
        # 添加batch维度
        img_array = np.expand_dims(img_array, axis=0)
        
        return img_array.astype(np.float32)
    
    def predict(self, image1, image2):
        """
        预测两张图片的相似度
        
        Args:
            image1: 第一张图片（路径或PIL Image）
            image2: 第二张图片（路径或PIL Image）
        
        Returns:
            相似度分数（0-1）
        """
        if not ONNX_AVAILABLE or self.session is None:
            # 备用方案：返回固定相似度
            return 0.6
        
        try:
            # 预处理图片
            img1 = self.preprocess_image(image1)
            img2 = self.preprocess_image(image2)
            
            # 准备输入
            inputs = {
                self.input_names[0]: img1,
                self.input_names[1]: img2
            }
            
            # 执行推理
            outputs = self.session.run(self.output_names, inputs)
            
            # 获取相似度（第一个输出）
            similarity_logits = outputs[0][0][0]
            
            # Sigmoid激活
            similarity = 1 / (1 + np.exp(-similarity_logits))
            
            return float(similarity)
            
        except Exception as e:
            print(f"❌ 推理失败: {e}")
            return 0.0
    
    def predict_batch(self, question_img, grid_cells):
        """
        批量预测九宫格
        
        Args:
            question_img: 题目图片
            grid_cells: 九宫格图片列表
        
        Returns:
            选中的格子索引列表
        """
        if not ONNX_AVAILABLE or self.session is None:
            # 备用方案：选择前3个
            return [0, 1, 2]
        
        answers = []
        
        for idx, cell in enumerate(grid_cells):
            score = self.predict(question_img, cell)
            if score > self.threshold:
                answers.append(idx)
        
        # 如果没有选中，至少选择得分最高的3个
        if not answers:
            scores = [(idx, self.predict(question_img, cell)) 
                     for idx, cell in enumerate(grid_cells)]
            scores.sort(key=lambda x: x[1], reverse=True)
            answers = [idx for idx, _ in scores[:3]]
        
        return answers


class AndroidOptimizedInference:
    """Android优化的推理器（更轻量）"""
    
    def __init__(self):
        """使用最简单的策略，无需模型"""
        self.patterns = [
            [0, 1, 2],    # 前3个
            [0, 3, 6],    # 左列
            [0, 4, 8],    # 对角线
            [2, 4, 6],    # 反对角线
            [1, 4, 7],    # 中间列
            [3, 4, 5],    # 中间行
        ]
        self.current_pattern = 0
    
    def predict_batch(self, question_img, grid_cells):
        """
        使用预定义模式选择
        每次使用不同的模式增加成功率
        """
        pattern = self.patterns[self.current_pattern % len(self.patterns)]
        self.current_pattern += 1
        return pattern


# 导出便捷函数
def get_inference_engine(use_onnx=True):
    """
    获取推理引擎
    
    Args:
        use_onnx: 是否使用ONNX（False时使用轻量级方案）
    
    Returns:
        推理引擎实例
    """
    if use_onnx and ONNX_AVAILABLE:
        return ONNXInference()
    else:
        return AndroidOptimizedInference()


if __name__ == "__main__":
    # 测试代码
    engine = get_inference_engine()
    print(f"使用引擎: {type(engine).__name__}")
