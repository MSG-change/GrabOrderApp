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
    from geetest_helper_optimized import GeetestHelperOptimized
    GEETEST_OPTIMIZED_AVAILABLE = True
except Exception:
    GEETEST_OPTIMIZED_AVAILABLE = False

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

# 优先级：优化版 > 远程 > 本地
GEETEST_AVAILABLE = GEETEST_OPTIMIZED_AVAILABLE or GEETEST_REMOTE_AVAILABLE or GEETEST_LOCAL_AVAILABLE

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
        self.user_server_area_id = config.get('user_server_area_id', '')  # 服务区域ID（空=所有区域）
        
        # 性能优化（极速版）
        self.executor = ThreadPoolExecutor(max_workers=20)  # 线程池 - 增加到20个
        self.order_cache = {}  # 订单缓存（避免重复抢单）
        self.cache_ttl = 15  # 缓存有效期（秒）- 减少到15秒避免错过重试机会
        
        # 🚀 智能两阶段缓存（正确的优化策略）
        self.recognition_cache = []  # 预识别结果缓存（可复用）
        self.max_recognition_cache = 10  # 最多缓存10个识别结果
        self.recognition_ttl = 300  # 识别结果有效期：5分钟（九宫格题目不变）
        self.preload_enabled = True  # 启用后台预加载
        
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
        
        # Voice notification settings
        self.enable_voice = config.get('enable_voice_notification', True)
        self._init_voice_notification()
        
        self.log("[INIT] Fast grab service initialized")
        self.log(f"  API: {self.api_base_url}")
        self.log(f"  Check interval: {self.check_interval}s")
        if self.user_server_area_id:
            self.log(f"  Server Area ID: {self.user_server_area_id}")
        else:
            self.log(f"  Server Area ID: All areas")
    
    def _create_optimized_session(self):
        """创建优化的 HTTP Session"""
        session = requests.Session()
        
        # 连接池配置（增加连接数，减少等待）
        adapter = HTTPAdapter(
            pool_connections=10,  # 连接池大小
            pool_maxsize=20,      # 最大连接数
            max_retries=Retry(
                total=3,          # 最多重试3次
                backoff_factor=0.3,  # 重试间隔（0.3s, 0.6s, 1.2s）
                status_forcelist=[500, 502, 503, 504],  # 需要重试的状态码
                raise_on_status=False  # 不抛出异常，返回响应
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
                kwargs['timeout'] = 15  # 默认15秒超时（网络较慢时）
            return original_request(*args, **kwargs)
        return wrapped_request
    
    def _init_voice_notification(self):
        """Initialize voice notification system"""
        self.tts_available = False
        self.audio_player = None
        
        try:
            # Check if running on Android
            if is_android:
                try:
                    from jnius import autoclass
                    self.tts_class = autoclass('android.speech.tts.TextToSpeech')
                    self.locale_class = autoclass('java.util.Locale')
                    # TTS will be initialized when first used (needs Activity context)
                    self.tts_available = True
                    self.log("[VOICE] Android TTS initialized")
                except Exception as e:
                    self.log(f"[VOICE] Android TTS init failed: {e}")
            else:
                # PC: Try pyttsx3 for TTS
                try:
                    import pyttsx3
                    self.tts_engine = pyttsx3.init()
                    self.tts_engine.setProperty('rate', 150)  # Speed
                    self.tts_engine.setProperty('volume', 1.0)  # Volume
                    self.tts_available = True
                    self.log("[VOICE] PC TTS (pyttsx3) initialized")
                except Exception as e:
                    self.log(f"[VOICE] PC TTS init failed: {e}")
                    # Fallback: try pygame for audio file playback
                    try:
                        import pygame
                        pygame.mixer.init()
                        self.audio_player = pygame.mixer
                        self.log("[VOICE] Audio player (pygame) initialized")
                    except Exception as e2:
                        self.log(f"[VOICE] Audio player init failed: {e2}")
        except Exception as e:
            self.log(f"[VOICE] Voice notification init failed: {e}")
    
    def _play_success_sound(self):
        """Play success notification sound"""
        if not self.enable_voice:
            return
        
        # Run in background thread to avoid blocking
        threading.Thread(target=self._play_success_sound_async, daemon=True).start()
    
    def _play_success_sound_async(self):
        """Play success sound asynchronously"""
        try:
            message = "抢单成功，快来看看"
            
            if is_android and self.tts_available:
                # Android TTS
                try:
                    from jnius import autoclass, cast
                    PythonActivity = autoclass('org.kivy.android.PythonActivity')
                    activity = PythonActivity.mActivity
                    
                    # Create TTS instance
                    tts = self.tts_class(activity, None)
                    time.sleep(0.5)  # Wait for TTS to initialize
                    
                    # Set Chinese locale
                    locale = self.locale_class.CHINESE
                    tts.setLanguage(locale)
                    
                    # Speak
                    tts.speak(message, self.tts_class.QUEUE_FLUSH, None, "success_notification")
                    self.log("[VOICE] Playing success notification (Android TTS)")
                except Exception as e:
                    self.log(f"[VOICE] Android TTS playback failed: {e}")
            
            elif self.tts_available and hasattr(self, 'tts_engine'):
                # PC TTS
                try:
                    self.tts_engine.say(message)
                    self.tts_engine.runAndWait()
                    self.log("[VOICE] Playing success notification (PC TTS)")
                except Exception as e:
                    self.log(f"[VOICE] PC TTS playback failed: {e}")
            
            elif self.audio_player:
                # Audio file playback (fallback)
                try:
                    # Look for success.mp3 in resources
                    audio_file = os.path.join(parent_dir, 'resources', 'success.mp3')
                    if not os.path.exists(audio_file):
                        # Try alternative locations
                        audio_file = os.path.join(parent_dir, 'success.mp3')
                    
                    if os.path.exists(audio_file):
                        self.audio_player.music.load(audio_file)
                        self.audio_player.music.play()
                        self.log(f"[VOICE] Playing audio file: {audio_file}")
                    else:
                        self.log(f"[VOICE] Audio file not found: {audio_file}")
                except Exception as e:
                    self.log(f"[VOICE] Audio playback failed: {e}")
            else:
                # No voice notification available
                self.log("[VOICE] Voice notification not available")
                
        except Exception as e:
            self.log(f"[VOICE] Error playing success sound: {e}")
    
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
        # 🚀 启动智能预加载（后台）- 秒抢模式加载更多
        if self.preload_enabled:
            preload_count = 10 if self.instant_mode else 3
            
            if self.instant_mode:
                self.log("⚡⚡⚡ Instant Grab Mode Initializing...", force=True)
            else:
                self.log("[INIT] Initializing grab service...")
            
            self.log(f"  Preloading {preload_count} recognition results...", force=True)
            
            # 提交预加载任务
            preload_futures = []
            for i in range(preload_count):
                future = self.executor.submit(self._preload_recognition)
                preload_futures.append(future)
            
            # 等待缓存预加载完成
            self.log(f"  Waiting for cache to build...", force=True)
            import concurrent.futures
            completed = 0
            failed = 0
            for i, future in enumerate(concurrent.futures.as_completed(preload_futures, timeout=60)):
                try:
                    success = future.result()  # 检查返回值
                    if success:
                        completed += 1
                        if completed % 3 == 0 or completed == preload_count:
                            self.log(f"  [CACHE] Preloaded {completed}/{preload_count} recognition results", force=True)
                    else:
                        failed += 1
                        self.log(f"  [CACHE] Preload task {i+1} returned False (possibly timeout or error)")
                except Exception as e:
                    failed += 1
                    self.log(f"  [CACHE] Preload task {i+1} failed with exception: {e}")
            
            cache_size = len(self.recognition_cache)
            if failed > 0:
                self.log(f"  ⚠️  {failed}/{preload_count} tasks failed", force=True)
            if cache_size > 0:
                self.log(f"  ✅ Cache ready: {cache_size} recognition results loaded", force=True)
            else:
                self.log(f"  ⚠️  Warning: Cache is empty, will use real-time verification", force=True)
        
        # 启动主循环线程
        self.thread.start()
        
        if self.instant_mode:
            self.log("⚡⚡⚡ Instant Grab Mode Started", force=True)
            self.log(f"  Check interval: {self.check_interval*1000:.0f}ms", force=True)
            self.log(f"  Concurrent threads: {self.executor._max_workers}", force=True)
            self.log(f"  Recognition cache: {len(self.recognition_cache)}/{self.max_recognition_cache} items ready", force=True)
            self.log(f"  Target speed: <1s", force=True)
        else:
            self.log("[STARTED] Grab service is running")
            self.log(f"  Check interval: {self.check_interval}s")
            self.log(f"  Category ID: {self.category_id}")
            self.log(f"  Recognition cache: {len(self.recognition_cache)} items ready")
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
                        self.log(f"[CHECKING] No orders (checked {self.stats['checks']} times)", force=True)
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
                'userServerAreaId': self.user_server_area_id  # Support multi-area
            }
            
            response = self.session.get(url, params=params, timeout=15)  # 15秒超时
            
            # Log response status (force in instant mode for debugging)
            if response.status_code != 200:
                self.log(f"[ERROR] HTTP {response.status_code}: {response.text[:100]}", force=True)
            
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
        
        except requests.exceptions.Timeout:
            self.log("[ERROR] Request timeout (5s)", force=True)
            return []
        except requests.exceptions.RequestException as e:
            self.log(f"[ERROR] Network error: {str(e)}", force=True)
            return []
        except Exception as e:
            self.log(f"[ERROR] Failed to get orders: {str(e)}", force=True)
            import traceback
            self.log(f"[ERROR] Traceback: {traceback.format_exc()[:200]}", force=True)
            return []
    
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
                self.log(f"[ERROR] Failed to get order ID from order: {order}", force=True)
                return False
            id_time = (time.time() - t1) * 1000
            
            order_id_str = str(order_id)
            
            self.log(f"[GRAB] Attempting to grab order: {order_id}", force=True)
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
                self.log(f"  [SUCCESS] Order {order_id} grabbed in {total_time:.1f}ms", force=True)
                self.order_cache[order_id] = time.time()
                return True
            else:
                self.stats['grab_failed'] += 1
                self.stats['grab_attempts'] += 1
                self.log(f"  [FAILED] Order {order_id} failed in {total_time:.1f}ms", force=True)
                return False
        
        except Exception as e:
            self.stats['grab_failed'] += 1
            self.log(f"  [ERROR] Grab exception: {str(e)}", force=True)
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
            
            # 🚀 智能两阶段缓存策略
            # 阶段1：尝试使用缓存的识别结果（省~1000ms）
            # 阶段2：用正确的challenge生成W参数（确保正确性）
            verify_start = time.time()
            
            cached_answers = self._get_cached_recognition()
            if cached_answers:
                # 使用缓存的识别 + 实时W生成
                self.log(f"  [GEETEST] Using cached recognition + real-time W generation ⚡")
                geetest_result = self.geetest_helper.verify_with_answers(
                    challenge=challenge,
                    answers=cached_answers
                )
            else:
                # 完全实时验证
                self.log(f"  [GEETEST] Full real-time verification (AI + W generation)...")
                geetest_result = self.geetest_helper.verify(challenge=challenge)
                # 触发预加载，为下次做准备
                if self.preload_enabled:
                    self.executor.submit(self._preload_recognition)
            
            verify_time = (time.time() - verify_start) * 1000
            
            self.log(f"  [GEETEST] Verification time: {verify_time:.1f}ms")
            
            if not geetest_result or not geetest_result.get('success'):
                self.log(f"  [GEETEST] ❌ Verification FAILED", force=True)
                if geetest_result:
                    self.log(f"  [GEETEST] Error: {geetest_result.get('error', 'Unknown')}", force=True)
                return False
            
            self.log(f"  [GEETEST] ✅ Verification SUCCESS", force=True)
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
                self.log(f"    ❌ lotNumber: MISSING", force=True)
            else:
                self.log(f"    ✅ lotNumber: {gee_dto['lotNumber'][:30]}...")
            
            if not gee_dto.get('captchaOutput'):
                missing_params.append('captchaOutput')
                self.log(f"    ❌ captchaOutput: MISSING", force=True)
            else:
                w_len = len(gee_dto['captchaOutput'])
                self.log(f"    ✅ captchaOutput: {w_len} chars")
                if w_len < 1000:
                    self.log(f"    ⚠️  WARNING: W parameter too short! Expected 1280, got {w_len}")
                self.log(f"    W param first 50 chars: {gee_dto['captchaOutput'][:50]}...")
            
            if not gee_dto.get('passToken'):
                missing_params.append('passToken')
                self.log(f"    ❌ passToken: MISSING", force=True)
            else:
                self.log(f"    ✅ passToken: {gee_dto['passToken'][:30]}...")
            
            self.log(f"    ✅ genTime: {gee_dto.get('genTime')}")
            self.log(f"    ✅ captchaId: {gee_dto.get('captchaId')}")
            self.log(f"    ✅ captchaKeyType: {gee_dto.get('captchaKeyType')}")
            
            if missing_params:
                self.log(f"  [GEEDTO] ❌ Missing required params: {', '.join(missing_params)}", force=True)
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
                self.log(f"  [RESPONSE] ❌ Parse FAILED: {e}", force=True)
                self.log(f"  [RESPONSE] Raw response: {response.text[:200]}", force=True)
                return False
            
            if result.get('code') == 200 or result.get('code') == 0:
                self.log(f"  [SUCCESS] ✅ Order grabbed successfully!", force=True)
                self.log(f"  [SUCCESS] Response message: {result.get('msg', 'N/A')}")
                self.order_cache[order_id] = time.time()
                
                # Play success notification sound
                self._play_success_sound()
                
                return True
            else:
                self.log(f"  [FAILED] ❌ Grab FAILED", force=True)
                self.log(f"  [FAILED] Error code: {result.get('code')}", force=True)
                self.log(f"  [FAILED] Error message: {result.get('msg')}", force=True)
                self.log(f"  [FAILED] Full response: {result}")
                
                # 特定错误码标记缓存
                if result.get('code') in [500, 404, 400]:
                    self.log(f"  [CACHE] Marked order {order_id} as processed")
                    self.order_cache[order_id] = time.time()
                
                return False
        
        except Exception as e:
            self.log(f"  [ERROR] Geetest exception: {e}", force=True)
            import traceback
            self.log(f"  [ERROR] Traceback: {traceback.format_exc()[:300]}", force=True)
            return False
    
    # ========================================================================
    # 🚀 智能两阶段缓存（正确的优化策略）
    # ========================================================================
    # 策略：分离识别和W生成，只缓存识别结果
    # 
    # 阶段1 - 预识别（可缓存）：
    #   - 提前下载并识别九宫格图片
    #   - 缓存识别答案 [1, 4, 7] 等
    #   - 有效期5分钟（九宫格题库不常变）
    # 
    # 阶段2 - 实时W生成（不可缓存）：
    #   - 使用正确的 challenge（基于订单ID）
    #   - 使用缓存的识别答案
    #   - 快速生成W参数（本地，无需AI）
    # 
    # 优势：
    #   - 节省AI识别时间（~1000ms）
    #   - challenge 始终正确
    #   - 总耗时从 2000ms 降至 ~600ms
    # ========================================================================
    
    def _preload_recognition(self):
        """后台预加载识别结果（智能缓存）- 同步版本"""
        try:
            if not self.preload_enabled:
                return False
            
            if len(self.recognition_cache) >= self.max_recognition_cache:
                return False  # 缓存已满
            
            if not hasattr(self, 'geetest_helper') or not self.geetest_helper:
                return False
            
            # 只获取AI识别结果，不生成W参数
            import uuid
            temp_challenge = str(uuid.uuid4())
            
            # 同步识别并添加到缓存
            result = self._recognize_only(temp_challenge)
            if result and result.get('success'):
                self.recognition_cache.append({
                    'answers': result.get('answers'),
                    'image_hash': result.get('image_hash'),  # 图片指纹
                    'time': time.time()
                })
                return True
            else:
                return False
                
        except Exception as e:
            self.log(f"[CACHE] Preload exception: {e}")
            return False
    
    def _recognize_only(self, challenge):
        """仅执行AI识别，不生成W参数"""
        try:
            # 调用AI识别接口（增加超时到15秒）
            if hasattr(self.geetest_helper, 'get_ai_answer'):
                result = self.geetest_helper.get_ai_answer(challenge=challenge, timeout=15)
                if result and result.get('success'):
                    return {
                        'success': True,
                        'answers': result.get('answers'),
                        'image_hash': result.get('image_hash', challenge[:8])
                    }
                else:
                    # 记录失败原因
                    error = result.get('error', 'Unknown') if result else 'No result'
                    self.log(f"[RECOGNIZE] Failed: {error}")
            return {'success': False}
        except Exception as e:
            self.log(f"[RECOGNIZE] Exception: {e}")
            return {'success': False}
    
    def _get_cached_recognition(self):
        """获取缓存的识别结果"""
        while self.recognition_cache:
            # 检查最老的缓存
            cached = self.recognition_cache[0]
            age = time.time() - cached['time']
            
            if age < self.recognition_ttl:
                # 有效，使用它
                result = self.recognition_cache.pop(0)
                self.log(f"[CACHE] Using cached recognition ⚡ (age: {age:.1f}s)")
                # 触发新的预加载
                if self.preload_enabled:
                    self.executor.submit(self._preload_recognition)
                return result['answers']
            else:
                # 过期，移除
                self.log(f"[CACHE] Recognition expired ({age:.1f}s)")
                self.recognition_cache.pop(0)
        
        return None
    
    def _init_geetest(self):
        """初始化 Geetest 识别器"""
        if self._geetest_initialized:
            return
        
        try:
            self.log("[INIT] Loading Geetest solver...")
            
            # 🚀 优先使用优化版（最快，本地W生成+远程AI识别）
            if GEETEST_OPTIMIZED_AVAILABLE:
                self.log("[INIT] Using OPTIMIZED helper (best performance) 🚀")
                self.geetest_helper = GeetestHelperOptimized(
                    ai_server_url=os.environ.get('AI_SERVER_URL', 'http://154.219.127.13:8889'),
                    captcha_id="045e2c229998a88721e32a763bc0f7b8"
                )
                self._geetest_initialized = True
                self.log("[OK] Optimized helper initialized ✅")
                self.log("   - AI识别: Remote (fast endpoint)")
                self.log("   - W生成: Local (no network delay)")
                self.log("   - Verify: Local (direct to target)")
                return
            
            # 降级到完整远程AI（稳定可靠）
            if GEETEST_REMOTE_AVAILABLE:
                self.log("[INIT] Using remote AI service (fallback)")
                self.geetest_helper = GeetestHelperRemote(
                    captcha_id="045e2c229998a88721e32a763bc0f7b8"
                )
                self._geetest_initialized = True
                self.log("[OK] Remote AI initialized ✅")
                return
            
            # 最后降级到本地模型
            if not GEETEST_AVAILABLE or not W_GENERATOR_AVAILABLE:
                self.log("[WARNING] Geetest modules not available")
                return
            
            self.log("[INIT] Using local model (last fallback)")
            
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
        # 测试确认：API需要的是id字段（内部ID），不是no（订单号）
        order_id = None
        
        # 按优先级尝试不同字段
        for field in ['id', 'orderId', 'orderNo', 'order_id', 'no']:
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
        """Log output (reduced logs in instant mode)"""
        if self.skip_logs and not force:
            # In instant mode, only output important logs
            important_keywords = [
                # English keywords
                'SUCCESS', 'FAILED', 'ERROR', 'WARNING', 'FOUND', 'GRABBED',
                'STARTED', 'STOPPED', 'INSTANT', 'GEETEST',
                # Chinese keywords (for compatibility)
                '成功', '失败', '错误', '启动', '停止', '秒抢'
            ]
            if any(keyword in message for keyword in important_keywords):
                pass  # Output
            else:
                return  # Skip
        
        if self.log_callback:
            # Ensure consistent time format
            timestamp = time.strftime('%H:%M:%S', time.localtime())
            self.log_callback(f"[{timestamp}] {message}")
        else:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")
