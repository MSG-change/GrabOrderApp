#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
抢单服务
集成 Geetest 识别和自动抢单逻辑
"""

import os
import sys
import time
import requests
import threading
from datetime import datetime

# 导入Geetest模块（从libs目录）
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
libs_dir = os.path.join(parent_dir, 'libs')
sys.path.insert(0, libs_dir)

# 尝试导入Geetest相关模块
try:
    from geetest_helper_local import GeetestHelperLocal
    print("✅ GeetestHelperLocal 导入成功")
except ImportError as e:
    print(f"⚠️ GeetestHelperLocal 导入失败: {e}")
    GeetestHelperLocal = None

try:
    # 根据环境选择W生成器
    try:
        from jnius import autoclass
        # Android环境：使用远程API
        from android_w_generator import AndroidWGenerator as LocalWGenerator
        print("✅ AndroidWGenerator 导入成功")
    except ImportError:
        # PC环境：使用本地JS
        from local_w_generator import LocalWGenerator
        print("✅ LocalWGenerator 导入成功")
except ImportError as e:
    print(f"⚠️ W生成器导入失败: {e}")
    LocalWGenerator = None


class GrabOrderService:
    """抢单服务"""
    
    def __init__(self, phone, api_base_url, log_callback=None):
        """
        初始化
        
        Args:
            phone: 手机号
            api_base_url: API 基础地址
            log_callback: 日志回调函数
        """
        self.phone = phone
        self.api_base_url = api_base_url.rstrip('/')
        self.log_callback = log_callback
        
        # 认证信息
        self.token = None
        self.headers = {
            'Content-Type': 'application/json',
            'user-agent': 'Mozilla/5.0 (Linux; Android 12; 23127PN0CC Build/W528JS; wv) AppleWebKit/537.36',
            'Host': 'dysh.dyswl.com',
        }
        
        # Geetest 识别器（安全加载）
        self.geetest_helper = None
        self.w_generator = None
        
        try:
            if GeetestHelperLocal and LocalWGenerator:
                self.log("🔧 正在初始化Geetest识别器...")
                
                # 确定模型路径（Android vs PC）
                if os.path.exists('/data/data'):  # Android环境
                    # Android：尝试多个可能的路径
                    possible_paths = [
                        os.path.join(parent_dir, 'assets', 'best_siamese_model.onnx'),
                        'assets/best_siamese_model.onnx',
                        'best_siamese_model.onnx',
                    ]
                    model_path = None
                    for path in possible_paths:
                        if os.path.exists(path):
                            model_path = path
                            self.log(f"   找到模型: {path}")
                            break
                    
                    if not model_path:
                        # 使用第一个路径，让GeetestHelper自己处理
                        model_path = possible_paths[0]
                        self.log(f"   使用默认路径: {model_path}")
                else:  # PC环境
                    model_path = "best_siamese_model.onnx"
                
                # 初始化Geetest Helper
                self.geetest_helper = GeetestHelperLocal(
                    model_path=model_path,
                    captcha_id="045e2c229998a88721e32a763bc0f7b8"
                )
                
                # 初始化W参数生成器
                self.w_generator = LocalWGenerator()
                
                self.log("✅ Geetest识别器加载成功")
            else:
                self.log("⚠️ Geetest模块未加载，验证码识别将被禁用")
                
        except Exception as e:
            self.log(f"⚠️ Geetest识别器加载失败: {e}")
            import traceback
            self.log(traceback.format_exc()[:200])  # 只显示前200字符
            self.geetest_helper = None
            self.w_generator = None
        
        # 运行控制
        self.running = False
        self.thread = None
        
        # 抢单参数
        self.category_id = "2469"  # 产品分类ID
        self.check_interval = 2  # 检查间隔（秒）
    
    def update_token(self, token, extra_headers=None):
        """
        更新 Token
        
        Args:
            token: 新的 Token
            extra_headers: 额外的 headers (club-id, role-id, tenant-id)
        """
        self.token = token
        self.headers['authorization'] = f'Bearer {token}'
        
        if extra_headers:
            for key, value in extra_headers.items():
                self.headers[key] = str(value)
        
        self.log(f"🔄 Token已更新: {token[:20]}...")
    
    def start(self):
        """启动抢单服务"""
        if self.running:
            self.log("⚠️ 服务已在运行中")
            return
        
        if not self.token:
            self.log("❌ 未配置Token，请先启用VPN抓包或手动配置")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        
        self.log("🚀 抢单服务已启动")
    
    def stop(self):
        """停止抢单服务"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)
        
        self.log("⏹️ 抢单服务已停止")
    
    def _run_loop(self):
        """主循环"""
        consecutive_errors = 0
        
        while self.running:
            try:
                # 获取订单列表
                orders = self._get_order_list()
                
                if orders:
                    self.log(f"📋 发现 {len(orders)} 个订单")
                    
                    # 尝试抢单
                    for order in orders:
                        if not self.running:
                            break
                        
                        success = self._grab_order(order)
                        if success:
                            self.log(f"🎉 抢单成功！订单ID: {order.get('id', 'Unknown')}")
                            break
                    
                    consecutive_errors = 0
                else:
                    consecutive_errors = 0
                
                # 等待下次检查
                time.sleep(self.check_interval)
            
            except Exception as e:
                consecutive_errors += 1
                self.log(f"❌ 错误: {e}")
                
                if consecutive_errors >= 5:
                    self.log("⚠️ 连续错误过多，增加检查间隔")
                    time.sleep(10)
                    consecutive_errors = 0
                else:
                    time.sleep(self.check_interval)
    
    def _get_order_list(self):
        """获取订单列表"""
        try:
            url = f"{self.api_base_url}/gate/app-api/club/order/getOrderPoolsList"
            params = {
                'productCategoryParentId': self.category_id,
                'userServerAreaId': ''
            }
            
            response = requests.get(
                url,
                params=params,
                headers=self.headers,
                timeout=10
            )
            
            data = response.json()
            
            if data.get('code') == 200:
                return data.get('data', [])
            elif data.get('code') == 403:
                self.log("⚠️ Token已过期，等待VPN捕获新Token...")
                return []
            else:
                self.log(f"⚠️ 获取订单失败: {data.get('msg', 'Unknown')}")
                return []
        
        except Exception as e:
            raise Exception(f"获取订单列表失败: {e}")
    
    def _grab_order(self, order):
        """
        抢单
        
        Args:
            order: 订单信息
        
        Returns:
            bool: 是否成功
        """
        try:
            order_id = order.get('id') or order.get('orderId') or order.get('order_id')
            if not order_id:
                self.log("⚠️ 订单ID缺失，跳过")
                return False
            
            self.log(f"🎯 正在抢单: {order_id}")
            
            # 可能需要 Geetest 验证
            if self._need_geetest_verification(order):
                if not self.geetest_helper or not self.w_generator:
                    self.log("❌ Geetest识别器未加载，无法抢单")
                    return False
                
                # 执行 Geetest 验证
                geetest_passed = self._solve_geetest()
                if not geetest_passed:
                    self.log("❌ Geetest验证失败")
                    return False
            
            # 提交抢单请求
            url = f"{self.api_base_url}/gate/app-api/club/order/grab"
            data = {
                'orderId': order_id
            }
            
            response = requests.post(
                url,
                json=data,
                headers=self.headers,
                timeout=10
            )
            
            result = response.json()
            
            if result.get('code') == 200:
                return True
            else:
                self.log(f"❌ 抢单失败: {result.get('msg', 'Unknown')}")
                return False
        
        except Exception as e:
            self.log(f"❌ 抢单异常: {e}")
            return False
    
    def _need_geetest_verification(self, order):
        """判断是否需要 Geetest 验证"""
        # 简单逻辑：高价值订单需要验证
        # 实际逻辑根据业务需求调整
        return True
    
    def _solve_geetest(self):
        """解决 Geetest 验证"""
        try:
            self.log("🔐 正在进行Geetest验证...")
            
            # 1. 获取验证码
            geetest_data = self.geetest_helper.load_geetest()
            if not geetest_data:
                return False
            
            lot_number = geetest_data.get('lot_number')
            question_url = f"http://static.geetest.com/{geetest_data['ques'][0]}"
            grid_url = f"http://static.geetest.com/{geetest_data['imgs']}"
            
            # 2. 识别图片
            pic_indices = self.geetest_helper.recognize_images(question_url, grid_url)
            if not pic_indices:
                return False
            
            self.log(f"✅ 识别结果: {pic_indices}")
            
            # 3. 生成 W 参数
            pic_index_str = ','.join(map(str, pic_indices))
            w_param = self.w_generator.generate_w(
                lot_number=lot_number,
                captcha_id=self.geetest_helper.captcha_id,
                pic_index=pic_index_str,
                **geetest_data['pow_detail']
            )
            
            if not w_param:
                return False
            
            # 4. 提交验证
            verify_success = self.geetest_helper.verify_geetest(
                lot_number=lot_number,
                captcha_output=w_param,
                pass_token=geetest_data['process_token'],
                gen_time=int(time.time())
            )
            
            if verify_success:
                self.log("✅ Geetest验证通过")
            
            return verify_success
        
        except Exception as e:
            self.log(f"❌ Geetest验证异常: {e}")
            return False
    
    def log(self, message):
        """输出日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] {message}"
        
        if self.log_callback:
            self.log_callback(log_msg)
        else:
            print(log_msg)

