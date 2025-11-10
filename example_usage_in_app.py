#!/usr/bin/env python3
"""
在 APP 中使用远程 AI 的示例代码
"""
import os
import requests

# 1. 设置远程 AI 服务器（在 main.py 中已经设置）
os.environ['AI_SERVER_URL'] = 'http://154.219.127.13:8889'

from libs.geetest_helper_local import GeetestHelper

# ============================================================================
# 示例1: 登录时使用（最常见）
# ============================================================================

def login_with_sms(phone, sms_code):
    """使用短信验证码登录"""
    
    BASE_URL = "https://app.shunshunxiaozhan.com"
    CAPTCHA_ID = "045e2c229998a88721e32a763bc0f7b8"
    
    # 步骤1: 初始化 GeetestHelper
    print("初始化验证码助手...")
    helper = GeetestHelper(captcha_id=CAPTCHA_ID)
    
    # 步骤2: 获取 challenge（APP 自动调用 API）
    print("获取验证码 challenge...")
    challenge_url = f"{BASE_URL}/driver/user/getGeetestChallenge"
    challenge_data = {
        "phone": phone,
        "captchaId": CAPTCHA_ID
    }
    
    response = requests.post(challenge_url, json=challenge_data)
    result = response.json()
    
    if result['code'] != 0:
        print(f"获取 challenge 失败: {result['msg']}")
        return False
    
    challenge = result['data']['challenge']
    print(f"Challenge: {challenge[:50]}...")
    
    # 步骤3: 使用远程 AI 识别验证码（自动完成）
    print("正在识别验证码（使用远程 AI）...")
    geetest_result = helper.verify(challenge)
    
    if not geetest_result or not geetest_result.get('success'):
        print("验证码识别失败")
        return False
    
    print("✅ 验证码识别成功")
    
    # 步骤4: 构造 geeDto
    gee_dto = {
        'lotNumber': geetest_result['lot_number'],
        'captchaOutput': geetest_result['captcha_output'],
        'passToken': geetest_result['pass_token'],
        'genTime': geetest_result['gen_time'],
        'captchaId': CAPTCHA_ID,
        'captchaKeyType': 'dlVerify'
    }
    
    # 步骤5: 登录
    print("正在登录...")
    login_url = f"{BASE_URL}/driver/user/loginBySms"
    login_data = {
        "phone": phone,
        "code": sms_code,
        "geeDto": gee_dto
    }
    
    response = requests.post(login_url, json=login_data)
    result = response.json()
    
    if result['code'] == 0:
        print("✅ 登录成功")
        return True, result['data']['token']
    else:
        print(f"❌ 登录失败: {result['msg']}")
        return False, None


# ============================================================================
# 示例2: 抢单时使用
# ============================================================================

def grab_order_with_geetest(order_id, token):
    """抢单时使用验证码"""
    
    BASE_URL = "https://app.shunshunxiaozhan.com"
    CAPTCHA_ID = "045e2c229998a88721e32a763bc0f7b8"
    
    # 步骤1: 初始化 GeetestHelper
    helper = GeetestHelper(captcha_id=CAPTCHA_ID)
    
    # 步骤2: 获取 challenge（从抢单接口的错误响应中获取）
    # 通常第一次抢单会返回需要验证码的错误，包含 challenge
    
    grab_url = f"{BASE_URL}/driver/order/grab"
    headers = {"Authorization": f"Bearer {token}"}
    
    # 第一次尝试（可能返回需要验证码）
    response = requests.post(
        grab_url,
        json={"orderId": order_id},
        headers=headers
    )
    result = response.json()
    
    # 如果需要验证码
    if result.get('code') == 4001:  # 假设 4001 表示需要验证码
        challenge = result.get('data', {}).get('challenge')
        
        if challenge:
            print("需要验证码，正在识别...")
            
            # 步骤3: 使用远程 AI 识别
            geetest_result = helper.verify(challenge)
            
            if geetest_result and geetest_result.get('success'):
                # 步骤4: 带验证码重新抢单
                gee_dto = {
                    'lotNumber': geetest_result['lot_number'],
                    'captchaOutput': geetest_result['captcha_output'],
                    'passToken': geetest_result['pass_token'],
                    'genTime': geetest_result['gen_time'],
                    'captchaId': CAPTCHA_ID,
                    'captchaKeyType': 'dlVerify'
                }
                
                response = requests.post(
                    grab_url,
                    json={
                        "orderId": order_id,
                        "geeDto": gee_dto
                    },
                    headers=headers
                )
                result = response.json()
    
    if result.get('code') == 0:
        print("✅ 抢单成功")
        return True
    else:
        print(f"❌ 抢单失败: {result.get('msg')}")
        return False


# ============================================================================
# 示例3: 最简化的使用方式（推荐）
# ============================================================================

class GrabOrderService:
    """抢单服务"""
    
    def __init__(self):
        self.base_url = "https://app.shunshunxiaozhan.com"
        self.captcha_id = "045e2c229998a88721e32a763bc0f7b8"
        self.geetest_helper = GeetestHelper(captcha_id=self.captcha_id)
    
    def get_geetest_result(self, phone_or_order_id):
        """
        获取验证码识别结果
        
        Args:
            phone_or_order_id: 手机号（登录）或订单ID（抢单）
        
        Returns:
            geeDto 字典，可直接用于登录或抢单
        """
        # 1. 获取 challenge
        challenge_url = f"{self.base_url}/driver/user/getGeetestChallenge"
        response = requests.post(
            challenge_url,
            json={
                "phone": phone_or_order_id,  # 或其他参数
                "captchaId": self.captcha_id
            }
        )
        
        result = response.json()
        if result['code'] != 0:
            return None
        
        challenge = result['data']['challenge']
        
        # 2. 使用远程 AI 识别（自动完成）
        geetest_result = self.geetest_helper.verify(challenge)
        
        if not geetest_result or not geetest_result.get('success'):
            return None
        
        # 3. 返回 geeDto
        return {
            'lotNumber': geetest_result['lot_number'],
            'captchaOutput': geetest_result['captcha_output'],
            'passToken': geetest_result['pass_token'],
            'genTime': geetest_result['gen_time'],
            'captchaId': self.captcha_id,
            'captchaKeyType': 'dlVerify'
        }
    
    def login(self, phone, sms_code):
        """登录"""
        gee_dto = self.get_geetest_result(phone)
        
        if not gee_dto:
            return False, "验证码识别失败"
        
        response = requests.post(
            f"{self.base_url}/driver/user/loginBySms",
            json={
                "phone": phone,
                "code": sms_code,
                "geeDto": gee_dto
            }
        )
        
        result = response.json()
        return result['code'] == 0, result.get('msg')
    
    def grab_order(self, order_id, token):
        """抢单"""
        # 先尝试不带验证码
        response = requests.post(
            f"{self.base_url}/driver/order/grab",
            json={"orderId": order_id},
            headers={"Authorization": f"Bearer {token}"}
        )
        
        result = response.json()
        
        # 如果需要验证码，自动处理
        if result.get('code') == 4001:  # 需要验证码
            gee_dto = self.get_geetest_result(order_id)
            
            if gee_dto:
                response = requests.post(
                    f"{self.base_url}/driver/order/grab",
                    json={
                        "orderId": order_id,
                        "geeDto": gee_dto
                    },
                    headers={"Authorization": f"Bearer {token}"}
                )
                result = response.json()
        
        return result['code'] == 0, result.get('msg')


# ============================================================================
# 使用示例
# ============================================================================

if __name__ == '__main__':
    # 创建服务实例
    service = GrabOrderService()
    
    # 登录
    success, msg = service.login("18113011654", "123456")
    print(f"登录: {success}, {msg}")
    
    # 抢单
    # success, msg = service.grab_order(order_id, token)
    # print(f"抢单: {success}, {msg}")
