#!/usr/bin/env python3
"""
ONNX版本的Siamese Network推理
使用Android ONNX Runtime (通过pyjnius调用Java API)
无numpy依赖版本 - 使用纯Python + PIL
"""

from PIL import Image
import math

try:
    # Android环境：使用pyjnius调用Java ONNX Runtime
    from jnius import autoclass
    
    # Java类
    OrtEnvironment = autoclass('ai.onnxruntime.OrtEnvironment')
    OrtSession = autoclass('ai.onnxruntime.OrtSession')
    OnnxTensor = autoclass('ai.onnxruntime.OnnxTensor')
    
    ANDROID_MODE = True
    HAS_NUMPY = False
except Exception:  # 捕获所有异常（包括 JavaException）
    # PC环境：使用Python onnxruntime
    try:
        import onnxruntime as ort
        import numpy as np
        ANDROID_MODE = False
        HAS_NUMPY = True
    except ImportError:
        ANDROID_MODE = False
        HAS_NUMPY = False


class SiameseONNX:
    """ONNX版本的孪生网络推理器（无numpy依赖）"""
    
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
        elif HAS_NUMPY:
            # PC: 使用Python onnxruntime
            print("   使用Python ONNX Runtime")
            self.session = ort.InferenceSession(
                model_path,
                providers=['CPUExecutionProvider']
            )
            self.input_names = [inp.name for inp in self.session.get_inputs()]
            self.output_names = [out.name for out in self.session.get_outputs()]  # 修复：out不是inp
        else:
            raise ImportError("需要numpy或Android环境")
        
        # 图像预处理参数 (ImageNet标准)
        self.mean = [0.485, 0.456, 0.406]
        self.std = [0.229, 0.224, 0.225]
    
    def preprocess(self, img: Image.Image):
        """
        预处理图像
        
        Args:
            img: PIL Image对象
        
        Returns:
            预处理后的数组 [1, 3, 224, 224]
        """
        # Resize
        img = img.resize((224, 224), Image.BILINEAR)
        
        if HAS_NUMPY:
            # PC: 使用numpy
            img_array = np.array(img, dtype=np.float32) / 255.0
            img_array = img_array.transpose(2, 0, 1)
            img_array = np.expand_dims(img_array, axis=0)
            # 标准化
            mean = np.array(self.mean, dtype=np.float32).reshape(1, 3, 1, 1)
            std = np.array(self.std, dtype=np.float32).reshape(1, 3, 1, 1)
            img_array = (img_array - mean) / std
            return img_array
        else:
            # Android: 使用纯Python + Java数组
            pixels = list(img.getdata())
            
            # 构建 [1, 3, 224, 224] 的Java float数组
            # 格式：[batch, channel, height, width]
            data = []
            
            # 对每个channel
            for c in range(3):  # R, G, B
                for y in range(224):
                    for x in range(224):
                        pixel = pixels[y * 224 + x]
                        value = pixel[c] / 255.0
                        # 标准化
                        value = (value - self.mean[c]) / self.std[c]
                        data.append(value)
            
            # 转换为Java float[]
            from jnius import cast
            FloatClass = autoclass('java.lang.Float')
            float_array = autoclass('[F')
            
            # 创建Java float数组
            jarray = float_array(len(data))
            for i, val in enumerate(data):
                jarray[i] = float(val)
            
            return jarray
    
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
            # 创建tensor shape: [1, 3, 224, 224]
            shape = [1, 3, 224, 224]
            LongClass = autoclass('java.lang.Long')
            long_array = autoclass('[J')
            shape_array = long_array(4)
            for i, s in enumerate(shape):
                shape_array[i] = LongClass(s).longValue()
            
            # 创建OnnxTensor
            tensor1 = OnnxTensor.createTensor(self.env, img1_array, shape_array)
            tensor2 = OnnxTensor.createTensor(self.env, img2_array, shape_array)
            
            # 创建输入map (Java HashMap)
            HashMap = autoclass('java.util.HashMap')
            inputs = HashMap()
            inputs.put(self.input_names[0], tensor1)
            inputs.put(self.input_names[1], tensor2)
            
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
        
        # 输出logits，需要sigmoid（纯Python实现）
        similarity = 1.0 / (1.0 + math.exp(-float(logits)))
        
        return float(similarity)


def get_transforms():
    """
    兼容性函数，返回None（ONNX版本不需要torchvision transforms）
    """
    return None, None

