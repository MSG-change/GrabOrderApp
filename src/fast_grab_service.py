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
    from geetest_helper_remote import GeetestHelperRemote
    GEETEST_REMOTE_AVAILABLE = True
except ImportError:
    GEETEST_REMOTE_AVAILABLE = False

try:
    from geetest_helper_local import GeetestHelperLocal
    GEETEST_LOCAL_AVAILABLE = True
except Exception:  # 捕获所有异常（包括模块内部的 JavaException）
    GEETEST_LOCAL_AVAILABLE = False

# 优先使用远程AI
GEETEST_AVAILABLE = GEETEST_REMOTE_AVAILABLE or GEETEST_LOCAL_AVAILABLE

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
        
        # 抢单参数（从配置读取）
        from src.config_manager import ConfigManager
        config_mgr = ConfigManager()
        config = config_mgr.load_config()
        self.category_id = config.get('category_id', '131')  # 使用配置中的值，默认131（考核单）
        self.check_interval = config.get('check_interval', 0.1)  # 检查间隔（秒）- 秒抢模式100ms
        
        # 性能优化（极速版）
        self.executor = ThreadPoolExecutor(max_workers=20)  # 线程池 - 增加到20个
        self.order_cache = {}  # 订单缓存（避免重复抢单）
        self.cache_ttl = 15  # 缓存有效期（秒）- 减少到15秒避免错过重试机会
        
        # 预验证缓存（加强版）
        self.verification_queue = []  # 预生成的验证缓存
        self.max_cache_size = 20  # 最多缓存20个验证
        self.verification_ttl = 90  # 验证缓存有效期：90秒（通用安全值）
        
        # 秒抢模式
        self.instant_mode = True  # 启用秒抢模式
        self.skip_logs = True  # 跳过详细日志（提速）
        
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
    
    def update_category_id(self, category_id):
        """
        动态更新产品分类ID
        
        Args:
            category_id: 新的产品分类ID
        """
        old_id = self.category_id
        self.category_id = str(category_id)
        if old_id != self.category_id:
            self.log(f"[CONFIG] Category ID updated: {old_id} -> {self.category_id}")
            # 清空订单缓存，因为分类变了
            self.order_cache.clear()
            self.log(f"[CACHE] Cleared order cache due to category change")
    
    def start(self):
        """启动抢单服务"""
        if self.running:
            self.log("[WARNING] Service already running")
            return
        
        # 清空缓存，确保新启动时没有旧缓存
        self.order_cache.clear()
        self.log("[CACHE] Cleared order cache on startup")
        
        # 初始化Geetest（提前准备）
        self._init_geetest()
        
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        
        # 启动预加载（后台）- 秒抢模式加载更多
        preload_count = 10 if self.instant_mode else 3
        for _ in range(preload_count):  # 预加载10个验证
            self.executor.submit(self._preload_verification)
        
        if self.instant_mode:
            self.log("⚡⚡⚡ Instant Grab Mode Started", force=True)
            self.log(f"  Check interval: {self.check_interval*1000:.0f}ms", force=True)
            self.log(f"  Concurrent threads: {self.executor._max_workers}", force=True)
            self.log(f"  Preload cache: {self.max_cache_size} items", force=True)
            self.log(f"  Target speed: <1s", force=True)
        else:
            self.log("[STARTED] Grab service is running")
            self.log(f"  Check interval: {self.check_interval}s")
            self.log(f"  Category ID: {self.category_id}")
            self.log(f"  Preload verification: Enabled")
            self.log(f"  Concurrent threads: {self.executor._max_workers}")
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
        """
        快速抢单（单个订单）
        直接进行Geetest验证，不先尝试空geeDto
        """
        total_start = time.time()
        try:
            # 步骤1：提取订单ID
            t1 = time.time()
            order_id = self._get_order_id(order)
            if not order_id:
                self.log(f"[ERROR] Failed to get order ID from order: {order}")
                return False
            id_time = (time.time() - t1) * 1000
            
            order_id_str = str(order_id)
            
            self.log(f"[GRAB] Attempting to grab order: {order_id}")
            self.log(f"  [TIMING] ID extraction: {id_time:.1f}ms")
            
            # 打印订单的其他关键字段
            if 'orderNo' in order:
                self.log(f"  [DEBUG] orderNo: {order.get('orderNo')}")
            if 'status' in order:
                self.log(f"  [DEBUG] status: {order.get('status')}")
            
            # ============================================================
            # 直接进行Geetest验证（不先尝试空geeDto）
            # ============================================================
            self.log(f"  [GEETEST] Starting verification...")
            success = self._grab_with_geetest(order_id_str)
            
            total_time = (time.time() - total_start) * 1000
            
            if success:
                self.stats['grab_success'] += 1
                self.stats['grab_attempts'] += 1
                self.stats['avg_grab_time'].append(total_time / 1000)
                self.log(f"  [SUCCESS] Order {order_id} grabbed in {total_time:.1f}ms")
                self.order_cache[order_id] = time.time()
                return True
            else:
                self.stats['grab_failed'] += 1
                self.stats['grab_attempts'] += 1
                self.log(f"  [FAILED] Order {order_id} failed in {total_time:.1f}ms")
                return False
        
        except Exception as e:
            self.stats['grab_failed'] += 1
            self.log(f"  [ERROR] Grab exception: {str(e)}")
            return False
    
    def _grab_with_geetest(self, order_id):
        """
        带 Geetest 验证的抢单
        流程：Load → 识别 → Verify → 抢单
        """
        try:
            # 延迟初始化 Geetest（避免启动慢）
            if not self._geetest_initialized:
                self._init_geetest()
            
            if not self.geetest_helper:
                self.log("  [WARNING] Geetest helper not available")
                return False
            
            # ============================================================
            # 步骤1-3: 执行完整的Geetest验证
            # Load → 识别 → 生成W → Verify
            # ============================================================
            self.log(f"  [GEETEST] Executing verification flow...")
            
            # 生成challenge（基于订单ID）
            challenge = self.geetest_helper.generate_challenge(str(order_id))
            self.log(f"  [GEETEST] Challenge: {challenge}")
            
            # 优先使用缓存的验证
            verify_start = time.time()
            geetest_result = self._get_cached_verification()
            
            if not geetest_result:
                # 缓存未命中，实时获取
                self.log(f"  [GEETEST] Real-time verification...")
                geetest_result = self.geetest_helper.verify(challenge=challenge)
            else:
                self.log(f"  [GEETEST] Using preloaded verification ⚡")
            
            verify_time = (time.time() - verify_start) * 1000
            
            self.log(f"  [GEETEST] Verification time: {verify_time:.1f}ms")
            
            if not geetest_result or not geetest_result.get('success'):
                self.log(f"  [GEETEST] ❌ Verification failed")
                if geetest_result:
                    self.log(f"  [GEETEST] Error: {geetest_result.get('error', 'Unknown')}")
                return False
            
            self.log(f"  [GEETEST] ✅ Verification successful")
            self.log(f"  [GEETEST] Recognized answers: {geetest_result.get('answers', [])}")
            
            # 详细检查返回的参数
            self.log(f"  [GEETEST] Response parameters check:")
            self.log(f"    - lot_number: {geetest_result.get('lot_number', 'MISSING')[:30]}...")
            self.log(f"    - captcha_output: {len(geetest_result.get('captcha_output', ''))} chars")
            self.log(f"    - pass_token: {geetest_result.get('pass_token', 'MISSING')[:30]}...")
            self.log(f"    - gen_time: {geetest_result.get('gen_time', 'MISSING')}")
            
            # ============================================================
            # 步骤4: 构建geeDto
            # ============================================================
            gee_dto = {
                'lotNumber': geetest_result.get('lot_number'),
                'captchaOutput': geetest_result.get('captcha_output'),
                'passToken': geetest_result.get('pass_token'),
                'genTime': str(geetest_result.get('gen_time', int(time.time()))),
                'captchaId': '045e2c229998a88721e32a763bc0f7b8',
                'captchaKeyType': 'dlVerify'
            }
            
            # 移除None值
            gee_dto = {k: v for k, v in gee_dto.items() if v is not None}
            
            # 详细验证每个必需参数
            self.log(f"  [GEEDTO] Build complete, verifying parameters:")
            
            missing_params = []
            if not gee_dto.get('lotNumber'):
                missing_params.append('lotNumber')
                self.log(f"    ❌ lotNumber: MISSING")
            else:
                self.log(f"    ✅ lotNumber: {gee_dto['lotNumber'][:30]}...")
            
            if not gee_dto.get('captchaOutput'):
                missing_params.append('captchaOutput')
                self.log(f"    ❌ captchaOutput: MISSING")
            else:
                w_len = len(gee_dto['captchaOutput'])
                self.log(f"    ✅ captchaOutput: {w_len} chars")
                if w_len < 1000:
                    self.log(f"    ⚠️  WARNING: W parameter too short! Expected 1280, got {w_len}")
                self.log(f"    W param first 50 chars: {gee_dto['captchaOutput'][:50]}...")
            
            if not gee_dto.get('passToken'):
                missing_params.append('passToken')
                self.log(f"    ❌ passToken: MISSING")
            else:
                self.log(f"    ✅ passToken: {gee_dto['passToken'][:30]}...")
            
            self.log(f"    ✅ genTime: {gee_dto.get('genTime')}")
            self.log(f"    ✅ captchaId: {gee_dto.get('captchaId')}")
            self.log(f"    ✅ captchaKeyType: {gee_dto.get('captchaKeyType')}")
            
            if missing_params:
                self.log(f"  [GEEDTO] ❌ Missing required params: {', '.join(missing_params)}")
                return False
            
            # ============================================================
            # 步骤5: 发送抢单请求（带geeDto）
            # ============================================================
            # 转换为整数格式（API要求）
            try:
                order_id_int = int(order_id)
            except (ValueError, TypeError):
                order_id_int = order_id
            
            payload = {
                'orderId': order_id_int,  # 整数格式
                'geeDto': gee_dto
            }
            
            # 使用官方APP的API端点
            url = f"{self.api_base_url}/gate/app-api/club/order/grabAnOrder/v1"
            
            self.log(f"  [REQUEST] POST /club/order/grabAnOrder/v1 with geeDto")
            self.log(f"  [GEEDTO] lotNumber: {gee_dto.get('lotNumber', 'N/A')[:20]}...")
            self.log(f"  [GEEDTO] captchaOutput length: {len(gee_dto.get('captchaOutput', ''))} chars")
            self.log(f"  [PAYLOAD] orderId: {order_id_int} (type: {type(order_id_int).__name__})")
            
            request_start = time.time()
            response = self.session.post(url, json=payload)
            request_time = (time.time() - request_start) * 1000
            
            self.log(f"  [RESPONSE] HTTP status: {response.status_code}")
            self.log(f"  [RESPONSE] Request time: {request_time:.1f}ms")
            
            try:
                result = response.json()
                self.log(f"  [RESPONSE] Response body: {result}")
            except Exception as e:
                self.log(f"  [RESPONSE] ❌ Parse failed: {e}")
                self.log(f"  [RESPONSE] Raw response: {response.text[:200]}")
                return False
            
            if result.get('code') == 200 or result.get('code') == 0:
                self.log(f"  [SUCCESS] ✅ Order grabbed successfully!")
                self.log(f"  [SUCCESS] Response message: {result.get('msg', 'N/A')}")
                self.order_cache[order_id] = time.time()
                return True
            else:
                self.log(f"  [FAILED] ❌ Grab failed")
                self.log(f"  [FAILED] Error code: {result.get('code')}")
                self.log(f"  [FAILED] Error message: {result.get('msg')}")
                self.log(f"  [FAILED] Full response: {result}")
                
                # 特定错误码标记缓存
                if result.get('code') in [500, 404, 400]:
                    self.log(f"  [CACHE] Marked order {order_id} as processed")
                    self.order_cache[order_id] = time.time()
                
                return False
        
        except Exception as e:
            self.log(f"  [ERROR] Geetest exception: {e}")
            return False
    
    def _preload_verification(self):
        """后台预加载验证码（提前准备）"""
        try:
            if len(self.verification_queue) >= self.max_cache_size:
                return  # 缓存已满
            
            # 使用远程AI服务
            if hasattr(self, 'geetest_helper') and self.geetest_helper:
                import uuid
                challenge = str(uuid.uuid4())
                
                # 异步获取验证
                future = self.executor.submit(
                    self.geetest_helper.verify, 
                    challenge=challenge
                )
                
                def cache_result(f):
                    try:
                        result = f.result(timeout=5)
                        if result and result.get('success'):
                            self.verification_queue.append({
                                'result': result,
                                'time': time.time()
                            })
                            self.log(f"[CACHE] Preloaded verification {len(self.verification_queue)}/{self.max_cache_size}")
                    except:
                        pass
                
                future.add_done_callback(cache_result)
        except:
            pass
    
    def _get_cached_verification(self):
        """获取缓存的验证（如果有）"""
        if self.verification_queue:
            # 检查最老的缓存是否过期
            age = time.time() - self.verification_queue[0]['time']
            
            if age < self.verification_ttl:  # 使用配置的TTL
                cached = self.verification_queue.pop(0)
                self.log(f"[VERIFY] Using cached verification ⚡ (age: {age:.1f}s)", force=True)
                # 触发新的预加载
                self.executor.submit(self._preload_verification)
                return cached['result']
            else:
                # 过期了，移除并尝试下一个
                self.log(f"[VERIFY] Cache expired ({age:.1f}s > {self.verification_ttl}s)")
                self.verification_queue.pop(0)
                return self._get_cached_verification()  # 递归检查下一个
        return None
    
    def _init_geetest(self):
        """初始化 Geetest 识别器"""
        if self._geetest_initialized:
            return
        
        try:
            self.log("[INIT] Loading Geetest solver...")
            
            # 优先使用远程AI（稳定可靠，避免W参数问题）
            if GEETEST_REMOTE_AVAILABLE:
                self.log("[INIT] Using remote AI service (recommended)")
                self.geetest_helper = GeetestHelperRemote(
                    captcha_id="045e2c229998a88721e32a763bc0f7b8"
                )
                self._geetest_initialized = True
                self.log("[OK] Remote AI initialized ✅")
                return
            
            # 降级到本地模型
            if not GEETEST_AVAILABLE or not W_GENERATOR_AVAILABLE:
                self.log("[WARNING] Geetest modules not available")
                return
            
            self.log("[INIT] Using local model (fallback)")
            
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
            self.log("[OK] Local model loaded")
        
        except Exception as e:
            self.log(f"[WARNING] Geetest load failed: {e}")
            import traceback
            self.log(traceback.format_exc()[:300])
    
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
    
    def log(self, message, force=False):
        """日志输出（秒抢模式下减少日志）"""
        if self.skip_logs and not force:
            # 秒抢模式只输出重要日志
            if any(keyword in message for keyword in ['成功', '失败', '错误', '启动', '停止', '秒抢']):
                pass  # 输出
            else:
                return  # 跳过
        
        if self.log_callback:
            # 确保时间格式一致
            timestamp = time.strftime('%H:%M:%S', time.localtime())
            self.log_callback(f"[{timestamp}] {message}")
        else:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")
