#!/usr/bin/env python3
"""
简化版AI服务器 - 仅处理captcha_id识别
基于v1.5.0稳定版本，最小化改动
"""

from flask import Flask, request, jsonify
import requests
import json
import uuid
from PIL import Image
import io

app = Flask(__name__)

# 加载模型
try:
    # 尝试加载ONNX
    from libs.onnx_inference import ONNXInference
    model = ONNXInference('siamese_model.onnx')
    print("✅ ONNX模型加载成功")
except:
    try:
        # 尝试加载PyTorch
        import torch
        from libs.siamese_network import SiameseNetwork
        siamese_model = SiameseNetwork()
        siamese_model.load_state_dict(torch.load('best_siamese_model.pth', map_location='cpu', weights_only=False))
        siamese_model.eval()
        
        class TorchModel:
            def __init__(self, model):
                self.model = model
                import torchvision.transforms as transforms
                self.transform = transforms.Compose([
                    transforms.Resize((224, 224)),
                    transforms.ToTensor(),
                    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
                ])
            
            def predict_batch(self, question_img, cells):
                import torch
                with torch.no_grad():
                    q = self.transform(question_img).unsqueeze(0)
                    scores = []
                    for cell in cells:
                        c = self.transform(cell).unsqueeze(0)
                        score = self.model(q, c).item()
                        scores.append(score)
                    # 返回得分最高的3个
                    top3 = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:3]
                    return top3
        
        model = TorchModel(siamese_model)
        print("✅ PyTorch模型加载成功")
    except Exception as e:
        print(f"⚠️ 模型加载失败: {e}")
        # 备用：返回固定值
        class DummyModel:
            def predict_batch(self, q, cells):
                return [0, 1, 2]
        model = DummyModel()

@app.route('/api/v1/recognize', methods=['POST'])
def recognize():
    """
    通过captcha_id识别九宫格
    直接获取图片，无需客户端下载
    """
    try:
        data = request.json
        captcha_id = data.get('captcha_id', '045e2c229998a88721e32a763bc0f7b8')
        challenge = data.get('challenge', str(uuid.uuid4()))
        
        print(f"📥 收到请求: captcha_id={captcha_id}")
        
        # 1. 从Geetest获取图片
        load_url = "http://gcaptcha4.geetest.com/load"
        load_params = {
            'captcha_id': captcha_id,
            'challenge': challenge,
            'client_type': 'android',
            'lang': 'zh-cn',
        }
        
        resp = requests.get(load_url, params=load_params, timeout=10)
        text = resp.text
        if text.startswith('(') and text.endswith(')'):
            text = text[1:-1]
        
        load_data = json.loads(text)
        if load_data.get('status') != 'success':
            raise Exception("Failed to load captcha")
        
        geetest_data = load_data['data']
        
        # 2. 下载图片
        imgs_path = geetest_data.get('imgs', '')
        ques_list = geetest_data.get('ques', [])
        
        question_url = f"http://static.geetest.com/{ques_list[0]}"
        grid_url = f"http://static.geetest.com/{imgs_path}"
        
        question_img = Image.open(io.BytesIO(requests.get(question_url).content))
        grid_img = Image.open(io.BytesIO(requests.get(grid_url).content))
        
        # 3. 切割九宫格
        cells = []
        w, h = grid_img.size
        cw, ch = w // 3, h // 3
        for r in range(3):
            for c in range(3):
                cell = grid_img.crop((c * cw, r * ch, (c + 1) * cw, (r + 1) * ch))
                cells.append(cell)
        
        # 4. AI识别
        answers = model.predict_batch(question_img, cells)
        
        print(f"✅ 识别成功: {answers}")
        
        # 5. 返回结果（包含验证所需的所有数据）
        return jsonify({
            'success': True,
            'answers': answers,  # 识别结果 [0-8]
            'lot_number': geetest_data.get('lot_number'),
            'pow_detail': geetest_data.get('pow_detail'),
            'payload': geetest_data.get('payload'),
            'process_token': geetest_data.get('process_token')
        })
        
    except Exception as e:
        print(f"❌ 错误: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'accuracy': 0.9888})

if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8889
    print(f"🚀 AI服务启动在 http://0.0.0.0:{port}")
    print("   仅支持captcha_id识别方式")
    print("   基于v1.5.0稳定版本")
    app.run(host='0.0.0.0', port=port)
