#!/usr/bin/env python3
"""
ONNX版本的Siamese Network推理
使用Android ONNX Runtime (通过pyjnius调用Java API)
"""

import numpy as np
from PIL import Image

try:
    # Android环境：使用pyjnius调用Java ONNX Runtime
    from jnius import autoclass
    
    # Java类
    OrtEnvironment = autoclass('ai.onnxruntime.OrtEnvironment')
    OrtSession = autoclass('ai.onnxruntime.OrtSession')
    OnnxTensor = autoclass('ai.onnxruntime.OnnxTensor')
    
    ANDROID_MODE = True
except ImportError:
    # PC环境：使用Python onnxruntime
    import onnxruntime as ort
    ANDROID_MODE = False


class SiameseONNX:
    """ONNX版本的孪生网络推理器"""
    
    def __init__(self, model_path: str):
        """
        初始化ONNX模型
        
        Args:
            model_path: ONNX模型文件路径
        """
        self.model_path = model_path
        
        if ANDROID_MODE:
            # Android: 使用Java ONNX Runtime
            print("   使用Android ONNX Runtime (Java)")
            self.env = OrtEnvironment.getEnvironment()
            self.session = self.env.createSession(model_path)
            self.input_names = ['input1', 'input2']  # 硬编码输入名称
            self.output_names = ['output']
        else:
            # PC: 使用Python onnxruntime
            print("   使用Python ONNX Runtime")
            self.session = ort.InferenceSession(
                model_path,
                providers=['CPUExecutionProvider']
            )
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
        
        if ANDROID_MODE:
            # Android: 使用Java ONNX Runtime推理
            # 创建Java端的输入tensor
            tensor1 = OnnxTensor.createTensor(self.env, img1_array)
            tensor2 = OnnxTensor.createTensor(self.env, img2_array)
            
            # 创建输入map
            inputs = {
                self.input_names[0]: tensor1,
                self.input_names[1]: tensor2
            }
            
            # 推理
            result = self.session.run(inputs)
            
            # 获取输出
            output_tensor = result.get(self.output_names[0])
            logits = output_tensor.getFloatBuffer().get(0)
            
            # 清理资源
            tensor1.close()
            tensor2.close()
            result.close()
        else:
            # PC: 使用Python onnxruntime推理
            outputs = self.session.run(
                self.output_names,
                {
                    self.input_names[0]: img1_array,
                    self.input_names[1]: img2_array
                }
            )
            logits = outputs[0][0]
        
        # 输出logits，需要sigmoid
        similarity = 1.0 / (1.0 + np.exp(-logits))  # sigmoid
        
        return float(similarity)


def get_transforms():
    """
    兼容性函数，返回None（ONNX版本不需要torchvision transforms）
    """
    return None, None

