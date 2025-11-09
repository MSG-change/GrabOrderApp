#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速抢单服务
使用异步请求、连接池、本地缓存等优化手段提升抢单速度
"""

import os
import sys
import time
import threading
import queue
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 导入 Geetest 相关模块
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
libs_dir = os.path.join(parent_dir, 'libs')
sys.path.insert(0, libs_dir)

try:
    from geetest_helper_local import GeetestHelperLocal
    GEETEST_AVAILABLE = True
except ImportError:
    GEETEST_AVAILABLE = False

try:
    import os
    is_android = os.path.exists('/data/data') or os.path.exists('/system/bin/app_process')
    
    if is_android:
        from android_w_generator import AndroidWGenerator as LocalWGenerator
    else:
        from local_w_generator import LocalWGenerator
    
    W_GENERATOR_AVAILABLE = True
except ImportError:
    W_GENERATOR_AVAILABLE = False
    LocalWGenerator = None


class FastGrabOrderService:
    """快速抢单服务（优化版）"""
    
    def __init__(self, api_base_url, log_callback=None):
        """
        初始化
        
        Args:
            api_base_url: API 基础地址
            log_callback: 日志回调函数
        """
        self.api_base_url = api_base_url.rstrip('/')
        self.log_callback = log_callback
        
        # 认证信息
        self.token = None
        self.headers = {
            'Content-Type': 'application/json',
            'user-agent': 'Mozilla/5.0 (Linux; Android 12; 23127PN0CC Build/W528JS; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)',
            'Host': 'dysh.dyswl.com',
        }
        
        # 创建优化的 Session（连接池 + 重试策略）
        self.session = self._create_optimized_session()
        self.session.headers.update(self.headers)
        
        # Geetest 识别器（延迟加载）
        self.geetest_helper = None
        self.w_generator = None
        self._geetest_initialized = False
        
        # 运行控制
        self.running = False
        self.thread = None
        
        # 抢单参数
        self.category_id = "131"  # Default from working script
        self.check_interval = 2  # 检查间隔（秒），默认2秒
        
        # 性能优化
        self.executor = ThreadPoolExecutor(max_workers=3)  # 线程池
        self.order_cache = {}  # 订单缓存（避免重复抢单）
        self.cache_ttl = 15  # 缓存有效期（秒）- 减少到15秒避免错过重试机会
        
        # 统计数据
        self.stats = {
            'checks': 0,
            'orders_found': 0,
            'grab_attempts': 0,
            'grab_success': 0,
            'grab_failed': 0,
            'avg_check_time': [],
            'avg_grab_time': [],
        }
        
        self.log("[INIT] Fast grab service initialized")
        self.log(f"  API: {self.api_base_url}")
        self.log(f"  Check interval: {self.check_interval}s")
    
    def _create_optimized_session(self):
        """创建优化的 HTTP Session"""
        session = requests.Session()
        
        # 连接池配置（增加连接数，减少等待）
        adapter = HTTPAdapter(
            pool_connections=10,  # 连接池大小
            pool_maxsize=20,      # 最大连接数
            max_retries=Retry(
                total=2,          # 最多重试2次
                backoff_factor=0.1,  # 重试间隔
                status_forcelist=[500, 502, 503, 504],  # 需要重试的状态码
            )
        )
        
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        # 设置超时（避免长时间等待）
        session.request = self._wrap_request_with_timeout(session.request)
        
        return session
    
    def _wrap_request_with_timeout(self, original_request):
        """包装请求方法，添加默认超时"""
        def wrapped_request(*args, **kwargs):
            if 'timeout' not in kwargs:
                kwargs['timeout'] = 5  # 默认5秒超时
            return original_request(*args, **kwargs)
        return wrapped_request
    
    def update_token(self, token_data):
        """
        更新 Token
        
        Args:
            token_data: Token 数据字典
        """
        self.token = token_data.get('token', '')
        
        if self.token:
            self.headers['authorization'] = f'Bearer {self.token}'
        
        # 更新其他 headers
        for key in ['club_id', 'role_id', 'tenant_id']:
            value = token_data.get(key)
            if value:
                # 转换 key 格式（club_id -> club-id）
                header_key = key.replace('_', '-')
                self.headers[header_key] = str(value)
        
        self.log(f"[TOKEN] Updated: {self.token[:20] if self.token else 'None'}...")
        
        # 更新 Session headers
        self.session.headers.update(self.headers)
        
        # Log headers for verification
        self.log(f"[HEADERS] authorization: {self.headers.get('authorization', 'NOT SET')[:30]}...")
        self.log(f"[HEADERS] club-id: {self.headers.get('club-id', 'NOT SET')}")
        self.log(f"[HEADERS] role-id: {self.headers.get('role-id', 'NOT SET')}")
        self.log(f"[HEADERS] tenant-id: {self.headers.get('tenant-id', 'NOT SET')}")
    
    def start(self):
        """启动抢单服务"""
        if self.running:
            self.log("[WARNING] Service already running")
            return
        
        # 清空缓存，确保新启动时没有旧缓存
        self.order_cache.clear()
        self.log("[CACHE] Cleared order cache on startup")
        
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        
        self.log("[STARTED] Grab service is running")
        self.log(f"  Check interval: {self.check_interval}s")
        self.log(f"  Category ID: {self.category_id}")
        return True
    
    def stop(self):
        """停止抢单服务"""
        self.running = False
        
        if self.thread:
            self.thread.join(timeout=3)
        
        if self.executor:
            self.executor.shutdown(wait=False)
        
        self.log("[STOPPED] Grab service stopped")
        self._print_stats()
    
    def _run_loop(self):
        """主循环"""
        consecutive_errors = 0
        check_count = 0  # Counter for heartbeat logging
        
        while self.running:
            try:
                start_time = time.time()
                
                # 获取订单列表
                orders = self._get_order_list()
                
                check_time = time.time() - start_time
                self.stats['checks'] += 1
                self.stats['avg_check_time'].append(check_time)
                
                if orders:
                    self.stats['orders_found'] += len(orders)
                    self.log(f"[FOUND] {len(orders)} order(s) available")
                    
                    # 添加缓存状态日志
                    if self.order_cache:
                        self.log(f"  [CACHE] {len(self.order_cache)} orders in cache: {list(self.order_cache.keys())[:3]}...")
                    
                    # Filter processed orders
                    new_orders = self._filter_new_orders(orders)
                    self.log(f"  [FILTER] {len(new_orders)} new orders after filtering")
                    
                    if new_orders:
                        # Log order details
                        for order in new_orders:
                            order_id = self._get_order_id(order)
                            order_name = order.get('productName', 'N/A')
                            order_price = order.get('orderPrice', 'N/A')
                            self.log(f"  Order ID: {order_id}")
                            self.log(f"  Product: {order_name}")
                            self.log(f"  Price: {order_price}")
                        
                        # Concurrent grab
                        self._grab_orders_concurrent(new_orders)
                    else:
                        self.log("  (All orders already processed)")
                        # 调试：显示被过滤的订单
                        if orders:
                            for order in orders[:1]:  # 只显示第一个
                                order_id = self._get_order_id(order)
                                if order_id in self.order_cache:
                                    self.log(f"    [DEBUG] Order {order_id} was filtered (in cache)")
                                else:
                                    self.log(f"    [DEBUG] Order {order_id} was filtered (unknown reason)")
                    
                    consecutive_errors = 0
                else:
                    # No orders - show heartbeat every 10 checks
                    check_count += 1
                    if check_count >= 10:
                        self.log(f"[CHECKING] No orders (checked {self.stats['checks']} times)")
                        check_count = 0
                
                # 动态调整检查间隔
                if orders:
                    # 有订单时检查更快
                    time.sleep(0.5)
                else:
                    time.sleep(self.check_interval)
            
            except Exception as e:
                consecutive_errors += 1
                error_msg = f"[ERROR] Check failed: {str(e)}"
                self.log(error_msg)
                
                if consecutive_errors >= 5:
                    self.log("[WARNING] Too many errors, pausing 10s...")
                    time.sleep(10)
                    consecutive_errors = 0
                else:
                    time.sleep(self.check_interval)
    
    def _get_order_list(self):
        """获取订单列表（快速版）"""
        try:
            url = f"{self.api_base_url}/gate/app-api/club/order/getOrderPoolsList"
            params = {
                'productCategoryParentId': self.category_id,
                'userServerAreaId': ''
            }
            
            # Log every request
            self.log(f"[REQUEST] GET {url}?productCategoryParentId={self.category_id}")
            
            response = self.session.get(url, params=params)
            
            # Log response
            self.log(f"[RESPONSE] Status: {response.status_code}")
            
            # Log response status for debugging
            if response.status_code != 200:
                self.log(f"[DEBUG] HTTP {response.status_code}: {response.text[:100]}")
            
            data = response.json()
            
            # API 返回 code=0 或 code=200 都表示成功
            if data.get('code') in [0, 200]:
                order_list = data.get('data', {})
                if isinstance(order_list, dict):
                    orders = order_list.get('list', [])
                    if orders:
                        self.log(f"[DEBUG] Found {len(orders)} orders in data.list")
                        # 打印第一个订单的所有键和部分值，用于调试
                        if orders and len(orders) > 0:
                            first_order = orders[0]
                            self.log(f"[DEBUG] Order keys: {list(first_order.keys())}")
                            # 打印重要字段
                            for key in ['id', 'orderId', 'orderNo', 'status', 'productName']:
                                if key in first_order:
                                    self.log(f"[DEBUG]   {key}: {first_order[key]}")
                    return orders
                elif isinstance(order_list, list):
                    if order_list:
                        self.log(f"[DEBUG] Found {len(order_list)} orders in data (list)")
                        if order_list and len(order_list) > 0:
                            first_order = order_list[0]
                            self.log(f"[DEBUG] Order keys: {list(first_order.keys())}")
                            # 打印重要字段
                            for key in ['id', 'orderId', 'orderNo', 'status', 'productName']:
                                if key in first_order:
                                    self.log(f"[DEBUG]   {key}: {first_order[key]}")
                    return order_list
                else:
                    self.log(f"[DEBUG] Unexpected data structure: {type(order_list)}")
                    return []
            elif data.get('code') == 403:
                self.log("[AUTH] Token expired, please update token")
                return []
            else:
                msg = data.get('msg', 'Unknown error')
                self.log(f"[API] Error code {data.get('code')}: {msg}")
                return []
        
        except Exception as e:
            raise Exception(f"Failed to get orders: {str(e)}")
    
    def _filter_new_orders(self, orders):
        """过滤新订单（避免重复抢单）"""
        current_time = time.time()
        new_orders = []
        
        for order in orders:
            order_id = self._get_order_id(order)
            if not order_id:
                continue
            
            # 检查缓存
            if order_id in self.order_cache:
                cache_time = self.order_cache[order_id]
                if current_time - cache_time < self.cache_ttl:
                    # 打印为什么跳过
                    time_left = self.cache_ttl - (current_time - cache_time)
                    self.log(f"  [SKIP] Order {order_id} in cache (wait {time_left:.1f}s)")
                    continue  # 跳过已处理的订单
            
            # 不要在这里标记！应该在抢单后标记
            # self.order_cache[order_id] = current_time
            new_orders.append(order)
        
        # 清理过期缓存
        self._clean_cache(current_time)
        
        return new_orders
    
    def _clean_cache(self, current_time):
        """清理过期缓存"""
        expired_keys = [
            k for k, v in self.order_cache.items()
            if current_time - v > self.cache_ttl
        ]
        for key in expired_keys:
            del self.order_cache[key]
    
    def _grab_orders_concurrent(self, orders):
        """并发抢单（提高速度）"""
        start_time = time.time()
        
        # 只抢前3个订单（避免过载）
        orders_to_grab = orders[:3]
        self.log(f"[GRAB] Starting concurrent grab for {len(orders_to_grab)} orders")
        
        futures = []
        for idx, order in enumerate(orders_to_grab):
            self.log(f"  [THREAD-{idx}] Submitting order to thread pool")
            future = self.executor.submit(self._grab_order_fast, order)
            futures.append(future)
        
        # 等待所有请求完成
        for idx, future in enumerate(futures):
            try:
                result = future.result(timeout=10)
                self.log(f"  [THREAD-{idx}] Completed with result: {result}")
            except Exception as e:
                self.log(f"  [THREAD-{idx}] Exception: {str(e)}")
        
        total_time = (time.time() - start_time) * 1000
        self.log(f"[GRAB] All concurrent grabs completed in {total_time:.1f}ms")
    
    def _grab_order_fast(self, order):
        """快速抢单（单个订单）"""
        total_start = time.time()
        try:
            # 步骤1：提取订单ID
            t1 = time.time()
            order_id = self._get_order_id(order)
            if not order_id:
                self.log(f"[ERROR] Failed to get order ID from order: {order}")
                return False
            id_time = (time.time() - t1) * 1000  # 转换为毫秒
            
            # 步骤2：准备请求数据
            t2 = time.time()
            url = f"{self.api_base_url}/gate/app-api/club/order/grabAnOrder/v1"
            
            # 确保 order_id 是字符串格式（API需要字符串，不是整数！）
            order_id_str = str(order_id)
            
            # 包含空的 geeDto 结构（即使不需要验证也要发送）
            data = {
                "orderId": order_id_str,  # 使用字符串格式
                "geeDto": {}  # 空的 geeDto，让服务器决定是否需要验证
            }
            prep_time = (time.time() - t2) * 1000
            
            self.log(f"[GRAB] Attempting to grab order: {order_id}")
            self.log(f"  [TIMING] ID extraction: {id_time:.1f}ms, Prep: {prep_time:.1f}ms")
            self.log(f"  [REQUEST] POST {url}")
            self.log(f"  [DATA] orderId='{order_id_str}' (type: {type(order_id_str).__name__}), geeDto={{}}")
            
            # 打印订单的其他关键字段，可能有用
            if 'orderNo' in order:
                self.log(f"  [DEBUG] orderNo: {order.get('orderNo')}")
            if 'status' in order:
                self.log(f"  [DEBUG] status: {order.get('status')}")
            
            # 步骤3：发送请求
            t3 = time.time()
            response = self.session.post(url, json=data)
            request_time = (time.time() - t3) * 1000
            
            # Log response
            self.log(f"  [RESPONSE] Status: {response.status_code} (took {request_time:.1f}ms)")
            
            # Log response for debugging
            if response.status_code != 200:
                self.log(f"  [DEBUG] HTTP {response.status_code}: {response.text[:100]}")
            
            # 步骤4：解析响应
            t4 = time.time()
            result = response.json()
            parse_time = (time.time() - t4) * 1000
            
            total_time = (time.time() - total_start) * 1000
            self.log(f"  [RESPONSE] Code: {result.get('code')}, Msg: {result.get('msg', 'N/A')}")
            self.log(f"  [TIMING] Request: {request_time:.1f}ms, Parse: {parse_time:.1f}ms, Total: {total_time:.1f}ms")
            
            self.stats['grab_attempts'] += 1
            self.stats['avg_grab_time'].append(total_time / 1000)  # 存储秒数
            
            # API 返回 code=0 或 code=200 都表示成功
            if result.get('code') in [0, 200]:
                self.stats['grab_success'] += 1
                self.log(f"  [SUCCESS] Order {order_id} grabbed in {total_time:.1f}ms")
                # 抢单成功后才缓存
                self.order_cache[order_id] = time.time()
                return True
            
            elif result.get('code') == 1001:
                # Needs Geetest verification
                self.log(f"  [CAPTCHA] Order {order_id} requires verification")
                success = self._grab_with_geetest(order_id_str)  # 传递字符串
                if success:
                    self.stats['grab_success'] += 1
                    return True
            
            else:
                self.stats['grab_failed'] += 1
                msg = result.get('msg', 'Unknown')
                code = result.get('code', 'N/A')
                self.log(f"  [FAILED] Order {order_id}: Code {code} - {msg}")
                # Code 500 "订单不存在" - 可能是订单已被抢或ID格式错误
                # 不缓存500错误，因为可能是ID问题而不是订单真的不存在
                if code in [404, 400]:  # 只缓存明确的失败
                    self.order_cache[order_id] = time.time()
                elif code == 500:
                    # 500错误可能是ID格式问题，不缓存，下次重试
                    self.log(f"  [DEBUG] Code 500 - not caching, might be ID format issue")
                return False
        
        except Exception as e:
            self.stats['grab_failed'] += 1
            self.log(f"  [ERROR] Grab exception: {str(e)}")
            return False
    
    def _grab_with_geetest(self, order_id):
        """带 Geetest 验证的抢单"""
        try:
            # 延迟初始化 Geetest（避免启动慢）
            if not self._geetest_initialized:
                self._init_geetest()
            
            if not self.geetest_helper or not self.w_generator:
                self.log("  [WARNING] Geetest solver not available")
                return False
            
            # 执行 Geetest 验证
            geetest_data = self.geetest_helper.load_geetest()
            if not geetest_data:
                return False
            
            lot_number = geetest_data.get('lot_number')
            question_url = f"http://static.geetest.com/{geetest_data['ques'][0]}"
            grid_url = f"http://static.geetest.com/{geetest_data['imgs']}"
            
            pic_indices = self.geetest_helper.recognize_images(question_url, grid_url)
            if not pic_indices:
                return False
            
            pic_index_str = ','.join(map(str, pic_indices))
            w_param = self.w_generator.generate_w(
                lot_number=lot_number,
                captcha_id=self.geetest_helper.captcha_id,
                pic_index=pic_index_str,
                **geetest_data['pow_detail']
            )
            
            if not w_param:
                return False
            
            # Get verification result
            geetest_result = self.geetest_helper.verify_geetest(
                lot_number=lot_number,
                captcha_output=w_param,
                pass_token=geetest_data['process_token'],
                gen_time=int(time.time())
            )
            
            if not geetest_result:
                return False
            
            # Build nested geeDto structure (matching working script)
            gee_dto = {
                'lotNumber': geetest_result.get('lot_number'),
                'captchaOutput': geetest_result.get('captcha_output'),
                'passToken': geetest_result.get('pass_token'),
                'genTime': str(geetest_result.get('gen_time', int(time.time()))),
                'captchaId': '045e2c229998a88721e32a763bc0f7b8',
                'captchaKeyType': 'dlVerify'
            }
            
            # Remove None values
            gee_dto = {k: v for k, v in gee_dto.items() if v is not None}
            
            # 确保 order_id 是字符串
            order_id_str = str(order_id)
            
            # Build payload with nested structure
            payload = {
                'orderId': order_id_str,  # 使用字符串
                'geeDto': gee_dto
            }
            
            # Send grab request with Geetest params
            url = f"{self.api_base_url}/gate/app-api/club/order/grabAnOrder/v1"
            
            self.log(f"  [REQUEST] POST grabAnOrder/v1 with geeDto")
            self.log(f"  [GEEDTO] lotNumber: {gee_dto.get('lotNumber', 'N/A')[:20]}...")
            
            response = self.session.post(url, json=payload)
            result = response.json()
            
            if result.get('code') == 200 or result.get('code') == 0:
                self.log(f"  [SUCCESS] Captcha solved, order grabbed!")
                # 验证码抢单成功后也要缓存
                self.order_cache[order_id] = time.time()
                return True
            else:
                self.log(f"  [FAILED] Captcha solved but grab failed: {result.get('msg')}")
                # 验证码失败根据错误码决定是否缓存
                if result.get('code') in [500, 404, 400]:
                    self.order_cache[order_id] = time.time()
                return False
        
        except Exception as e:
            self.log(f"  [ERROR] Geetest exception: {e}")
            return False
    
    def _init_geetest(self):
        """初始化 Geetest 识别器"""
        if self._geetest_initialized:
            return
        
        try:
            self.log("[INIT] Loading Geetest solver...")
            
            if not GEETEST_AVAILABLE or not W_GENERATOR_AVAILABLE:
                self.log("[WARNING] Geetest modules not available")
                return
            
            # 确定模型路径
            if os.path.exists('/data/data'):
                model_path = 'assets/best_siamese_model.onnx'
            else:
                model_path = 'best_siamese_model.onnx'
            
            self.geetest_helper = GeetestHelperLocal(
                model_path=model_path,
                captcha_id="045e2c229998a88721e32a763bc0f7b8"
            )
            
            self.w_generator = LocalWGenerator()
            
            self._geetest_initialized = True
            self.log("[OK] Geetest solver loaded")
        
        except Exception as e:
            self.log(f"[WARNING] Geetest load failed: {e}")
    
    def _get_order_id(self, order):
        """获取订单 ID"""
        # 尝试多种可能的字段名
        # 注意：可能需要 orderNo 而不是 id
        order_id = None
        
        # 按优先级尝试不同字段
        for field in ['orderNo', 'orderId', 'id', 'order_id']:
            if field in order and order[field]:
                order_id = order[field]
                self.log(f"  [ORDER_ID] Using field '{field}' = {order_id}")
                break
        
        if not order_id:
            self.log(f"[WARNING] Cannot find order ID in order data: {list(order.keys())}")
            # 打印前5个字段的值以便调试
            for key in list(order.keys())[:5]:
                self.log(f"    {key}: {order.get(key)}")
        
        return order_id
    
    def _print_stats(self):
        """Print statistics"""
        self.log("")
        self.log("[STATS] Service Statistics")
        self.log("-" * 50)
        self.log(f"Checks: {self.stats['checks']}")
        self.log(f"Orders found: {self.stats['orders_found']}")
        self.log(f"Grab attempts: {self.stats['grab_attempts']}")
        self.log(f"  Success: {self.stats['grab_success']}")
        self.log(f"  Failed: {self.stats['grab_failed']}")
        
        if self.stats['grab_attempts'] > 0:
            rate = self.stats['grab_success'] / self.stats['grab_attempts'] * 100
            self.log(f"Success rate: {rate:.1f}%")
        
        if self.stats['avg_check_time']:
            avg = sum(self.stats['avg_check_time']) / len(self.stats['avg_check_time'])
            self.log(f"Avg check time: {avg:.2f}s")
        
        if self.stats['avg_grab_time']:
            avg = sum(self.stats['avg_grab_time']) / len(self.stats['avg_grab_time'])
            self.log(f"Avg grab time: {avg:.2f}s")
        
        self.log("-" * 50)
    
    def log(self, message):
        """输出日志"""
        if self.log_callback:
            self.log_callback(message)
        else:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")
