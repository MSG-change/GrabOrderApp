#!/usr/bin/env python3
"""
ONNX版本的Siamese Network推理
专为Android APK优化
"""

import numpy as np
from PIL import Image
import onnxruntime as ort


class SiameseONNX:
    """ONNX版本的孪生网络推理器"""
    
    def __init__(self, model_path: str):
        """
        初始化ONNX模型
        
        Args:
            model_path: ONNX模型文件路径
        """
        # 加载ONNX模型
        self.session = ort.InferenceSession(
            model_path,
            providers=['CPUExecutionProvider']  # Android只用CPU
        )
        
        # 获取输入输出名称
        self.input_names = [inp.name for inp in self.session.get_inputs()]
        self.output_names = [out.name for out in self.session.get_outputs()]
        
        # 图像预处理参数 (ImageNet标准)
        self.mean = np.array([0.485, 0.456, 0.406], dtype=np.float32).reshape(1, 3, 1, 1)
        self.std = np.array([0.229, 0.224, 0.225], dtype=np.float32).reshape(1, 3, 1, 1)
    
    def preprocess(self, img: Image.Image) -> np.ndarray:
        """
        预处理图像
        
        Args:
            img: PIL Image对象
        
        Returns:
            预处理后的numpy数组 [1, 3, 224, 224]
        """
        # Resize
        img = img.resize((224, 224), Image.BILINEAR)
        
        # 转换为numpy数组 [H, W, C]
        img_array = np.array(img, dtype=np.float32) / 255.0
        
        # 转换为 [C, H, W]
        img_array = img_array.transpose(2, 0, 1)
        
        # 添加batch维度 [1, C, H, W]
        img_array = np.expand_dims(img_array, axis=0)
        
        # 标准化
        img_array = (img_array - self.mean) / self.std
        
        return img_array
    
    def predict(self, img1: Image.Image, img2: Image.Image) -> float:
        """
        预测两张图片的相似度
        
        Args:
            img1: 第一张图片
            img2: 第二张图片
        
        Returns:
            相似度分数 [0.0, 1.0]
        """
        # 预处理
        img1_array = self.preprocess(img1)
        img2_array = self.preprocess(img2)
        
        # 推理
        outputs = self.session.run(
            self.output_names,
            {
                self.input_names[0]: img1_array,
                self.input_names[1]: img2_array
            }
        )
        
        # 输出logits，需要sigmoid
        logits = outputs[0][0]  # [batch] -> scalar
        similarity = 1.0 / (1.0 + np.exp(-logits))  # sigmoid
        
        return float(similarity)


def get_transforms():
    """
    兼容性函数，返回None（ONNX版本不需要torchvision transforms）
    """
    return None, None

