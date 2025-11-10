#!/usr/bin/env python3
"""
Geetest 验证码助手 - 本地模型版
直接加载模型，无需启动API服务
"""

import requests
import json
import time
import hashlib
from typing import Optional, Dict, List
from PIL import Image
import io

# 条件导入本地模型（仅在未配置远程AI时需要）
try:
    from siamese_onnx import SiameseONNX
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False
    SiameseONNX = None

# 根据环境选择W参数生成器
import os
is_android = os.path.exists('/data/data') or os.path.exists('/system/bin/app_process')

LocalWGenerator = None
W_GENERATOR_AVAILABLE = False

if is_android:
    # Android环境：使用本地 WebView 方案
    print("   🤖 Android环境 → 使用本地 WebView 生成W参数")
    try:
        from android_local_w_generator import AndroidLocalWGenerator as LocalWGenerator
        W_GENERATOR_AVAILABLE = True
        print("      ✅ AndroidLocalWGenerator 加载成功")
    except ImportError as e:
        print(f"      ⚠️ AndroidLocalWGenerator 加载失败: {e}")
        try:
            from android_w_generator import AndroidWGenerator as LocalWGenerator
            W_GENERATOR_AVAILABLE = True
            print("      ✅ AndroidWGenerator 加载成功")
        except ImportError:
            print("      ⚠️ 所有 Android W生成器都不可用")
else:
    # PC环境：尝试使用本地JS
    print("   💻 PC环境 → 尝试使用本地JS生成W参数")
    try:
        from local_w_generator import LocalWGenerator
        W_GENERATOR_AVAILABLE = True
        print("      ✅ LocalWGenerator加载成功（需要Node.js）")
    except ImportError as e:
        print(f"      ⚠️ LocalWGenerator加载失败: {e}")
        try:
            from android_w_generator import AndroidWGenerator as LocalWGenerator
            W_GENERATOR_AVAILABLE = True
            print("      ✅ AndroidWGenerator 加载成功（回退）")
        except ImportError:
            print("      ⚠️ 所有 W生成器都不可用")


class GeetestHelperLocal:
    """Geetest 验证码助手（本地模型）"""
    
    def __init__(self,
                 model_path: str = "best_siamese_model.onnx",
                 captcha_id: str = "045e2c229998a88721e32a763bc0f7b8",
                 threshold: float = 0.5,
                 js_file_path: str = None):
        """
        初始化
        
        Args:
            model_path: ONNX模型文件路径
            captcha_id: Geetest的captcha_id
            threshold: 相似度阈值
            js_file_path: gcaptcha4_click.js 文件路径（可选）
        """
        print("🔧 初始化 Geetest 验证器（ONNX模型 + 本地W参数）...")
        
        self.captcha_id = captcha_id
        self.threshold = threshold
        
        # 初始化本地 W 参数生成器
        if W_GENERATOR_AVAILABLE and LocalWGenerator is not None:
            try:
                self.w_generator = LocalWGenerator(js_file_path=js_file_path)
            except Exception as e:
                print(f"   ⚠️  W参数生成器初始化失败: {e}")
                print(f"   将在运行时使用远程AI服务")
                self.w_generator = None
        else:
            print(f"   ⚠️  W参数生成器不可用，将使用远程AI服务")
            self.w_generator = None
        
        # 加载ONNX模型（如果配置了远程AI，跳过本地模型）
        ai_server_url = os.environ.get('AI_SERVER_URL')
        if ai_server_url:
            print(f"   🌐 已配置远程AI服务，跳过本地模型加载")
            self.model = None
        elif not ONNX_AVAILABLE or SiameseONNX is None:
            print(f"   ⚠️  ONNX模块不可用，将使用远程AI服务")
            self.model = None
        else:
            print(f"   加载ONNX模型: {model_path}")
            try:
                self.model = SiameseONNX(model_path)
                print(f"   ✅ ONNX模型加载成功")
            except Exception as e:
                print(f"   ⚠️  ONNX模型加载失败: {e}")
                print(f"   📌 将使用远程AI服务")
                self.model = None
        
        # Android 客户端请求头
        self.android_headers = {
            'Host': 'gcaptcha4.geetest.com',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 12; 23127PN0CC Build/W528JS; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)',
            'Accept': '*/*',
            'X-Requested-With': 'com.dys.shzs',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
        }
        
        print("✅ 初始化完成")
    
    def download_image(self, url: str) -> Optional[Image.Image]:
        """下载图片"""
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            img = Image.open(io.BytesIO(response.content)).convert('RGB')
            return img
        except Exception as e:
            print(f"   下载图片失败: {e}")
            return None
    
    def split_grid(self, grid_img: Image.Image) -> List[Image.Image]:
        """切割九宫格"""
        width, height = grid_img.size
        cell_width = width // 3
        cell_height = height // 3
        
        cells = []
        for row in range(3):
            for col in range(3):
                left = col * cell_width
                top = row * cell_height
                right = left + cell_width
                bottom = top + cell_height
                
                cell = grid_img.crop((left, top, right, bottom))
                cells.append(cell)
        
        return cells
    
    def predict_similarity(self, question_img: Image.Image, candidate_img: Image.Image) -> float:
        """预测相似度"""
        try:
            # ONNX推理
            prob = self.model.predict(question_img, candidate_img)
            return prob
        except Exception as e:
            print(f"   预测失败: {e}")
            return 0.0
    
    def recognize(self, question_url: str, grid_url: str) -> List[int]:
        """
        识别验证码
        
        Args:
            question_url: 题目图片URL
            grid_url: 九宫格图片URL
        
        Returns:
            答案索引列表 [0, 3, 8]
        """
        # 下载图片
        question_img = self.download_image(question_url)
        if question_img is None:
            return []
        
        grid_img = self.download_image(grid_url)
        if grid_img is None:
            return []
        
        # 切割九宫格
        cells = self.split_grid(grid_img)
        
        # 预测每个格子
        answers = []
        for idx, cell in enumerate(cells):
            score = self.predict_similarity(question_img, cell)
            if score > self.threshold:
                answers.append(idx)
        
        return answers
    
    def verify(self, challenge: Optional[str] = None) -> Optional[Dict]:
        """
        完整的 Geetest 验证流程
        
        Args:
            challenge: 可选的 challenge 参数
        
        Returns:
            验证结果字典或None
        """
        # 尝试使用远程AI服务（如果配置了）
        ai_server_url = os.environ.get('AI_SERVER_URL')
        if ai_server_url:
            try:
                print(f"   🌐 使用远程AI完整验证服务: {ai_server_url}")
                
                # 使用新的完整验证API - 直接返回所有必需参数
                response = requests.post(
                    f"{ai_server_url}/api/verify",
                    json={
                        'captcha_id': self.captcha_id,
                        'challenge': challenge,
                        'threshold': self.threshold
                    },
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('success'):
                        print(f"   ✅ 远程验证成功!")
                        print(f"      识别答案: {result.get('answers')}")
                        print(f"      Lot Number: {result.get('lot_number')}")
                        print(f"      W参数已生成: {result.get('captcha_output')[:20]}...")
                        
                        # 直接返回完整结果，不需要本地处理
                        return result
                    else:
                        print(f"   ⚠️  远程验证失败: {result.get('error')}")
                else:
                    print(f"   ⚠️  远程API响应异常: {response.status_code}")
                        
            except Exception as e:
                print(f"   ⚠️  远程AI失败: {e}，使用本地处理")
        
        # 原有的本地处理逻辑
        print("   📱 使用本地处理")
        session = requests.Session()
        
        try:
            # ============================================================
            # 步骤1: Load
            # ============================================================
            load_url = "http://gcaptcha4.geetest.com/load"
            load_params = {
                'captcha_id': self.captcha_id,
                'client_type': 'android',
                'lang': 'zh-cn',
            }
            
            if challenge:
                load_params['challenge'] = challenge
            
            load_response = session.get(
                load_url,
                params=load_params,
                headers=self.android_headers,
                timeout=10
            )
            
            response_text = load_response.text
            if response_text.startswith('(') and response_text.endswith(')'):
                response_text = response_text[1:-1]
            
            load_data = json.loads(response_text)
            
            if load_data.get('status') != 'success':
                return None
            
            geetest_data = load_data['data']
            lot_number = geetest_data['lot_number']
            pow_detail = geetest_data.get('pow_detail', {})
            payload = geetest_data.get('payload')
            process_token = geetest_data.get('process_token')
            
            # ============================================================
            # 步骤2: 本地模型识别
            # ============================================================
            imgs_path = geetest_data.get('imgs', '')
            ques_list = geetest_data.get('ques', [])
            
            if not imgs_path or not ques_list:
                return None
            
            question_path = ques_list[0] if isinstance(ques_list, list) else ques_list
            question_url = f"http://static.geetest.com/{question_path}"
            grid_url = f"http://static.geetest.com/{imgs_path}"
            
            # 使用远程识别结果（如果有）或本地识别
            if hasattr(self, '_remote_answers') and self._remote_answers:
                print(f"   ✅ 使用远程AI识别结果: {self._remote_answers}")
                answers = self._remote_answers
                delattr(self, '_remote_answers')  # 清除已使用的远程答案
            else:
                # 本地识别
                answers = self.recognize(question_url, grid_url)
            
            if not answers:
                return None
            
            # ============================================================
            # 步骤3: 本地生成W参数
            # ============================================================
            pic_index = ",".join(map(str, answers))
            
            # 生成 W 参数
            w_param = None
            if self.w_generator:
                try:
                    w_param = self.w_generator.generate_w(
                        lot_number=lot_number,
                        captcha_id=self.captcha_id,
                        version=str(pow_detail.get('version', '1')),
                        bits=int(pow_detail.get('bits', 0)),
                        datetime=pow_detail.get('datetime', ''),
                        hashfunc=pow_detail.get('hashfunc', 'md5'),
                        pic_index=pic_index
                    )
                except Exception as e:
                    print(f"   ⚠️  W参数生成失败: {e}")
            
            if not w_param:
                # W参数生成器不可用，使用简化的返回（仅用于测试）
                print(f"   ⚠️  W参数生成器不可用，返回识别结果（测试模式）")
                return {
                    'success': True,
                    'lot_number': lot_number,
                    'captcha_output': '',  # W参数为空
                    'pass_token': process_token,
                    'gen_time': int(time.time()),
                    'answers': answers
                }
            
            # ============================================================
            # 步骤4: Verify
            # ============================================================
            verify_url = "http://gcaptcha4.geetest.com/verify"
            
            verify_params = {
                'captcha_id': self.captcha_id,
                'client_type': 'android',
                'lot_number': lot_number,
                'payload': payload,
                'process_token': process_token,
                'payload_protocol': '1',
                'pt': '1',
                'w': w_param
            }
            
            if challenge:
                verify_params['challenge'] = challenge
            
            verify_response = session.get(
                verify_url,
                params=verify_params,
                headers=self.android_headers,
                timeout=10
            )
            
            verify_text = verify_response.text
            if verify_text.startswith('(') and verify_text.endswith(')'):
                verify_text = verify_text[1:-1]
            
            verify_result = json.loads(verify_text)
            
            # ============================================================
            # 返回结果
            # ============================================================
            if verify_result.get('status') == 'success':
                data = verify_result.get('data', {})
                result = data.get('result')
                
                if result == 'success':
                    seccode = data.get('seccode', {})
                    
                    return {
                        'success': True,
                        'lot_number': lot_number,
                        'pass_token': seccode.get('pass_token'),
                        'gen_time': seccode.get('gen_time'),
                        'captcha_output': seccode.get('captcha_output'),
                        'score': data.get('score'),
                        'answers': answers  # 额外返回识别结果
                    }
            
            return None
        
        except Exception as e:
            print(f"验证异常: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    @staticmethod
    def generate_challenge(text: str) -> str:
        """生成 challenge"""
        return hashlib.md5(f"{text}{int(time.time())}".encode()).hexdigest()


# 简化函数
def quick_verify_local(phone_or_text: Optional[str] = None,
                       model_path: str = "best_siamese_model.onnx") -> Optional[Dict]:
    """
    快速验证（ONNX模型）
    
    Args:
        phone_or_text: 手机号或其他文本
        model_path: ONNX模型文件路径
    
    Returns:
        验证结果字典或None
    """
    helper = GeetestHelperLocal(model_path=model_path)
    
    challenge = None
    if phone_or_text:
        challenge = helper.generate_challenge(phone_or_text)
    
    return helper.verify(challenge)


# 创建别名以保持向后兼容
GeetestHelper = GeetestHelperLocal


if __name__ == "__main__":
    # 测试
    print()
    print("=" * 70)
    print("🔐 Geetest 验证码助手 - 本地模型版")
    print("=" * 70)
    print()
    
    # 测试
    result = quick_verify_local("13800138000")
    
    if result:
        print()
        print("✅ 验证成功")
        print(f"   识别答案: {result['answers']}")
        print(f"   lot_number: {result['lot_number']}")
        print(f"   pass_token: {result['pass_token'][:50]}...")
        print(f"   score: {result['score']}")
    else:
        print()
        print("❌ 验证失败")

