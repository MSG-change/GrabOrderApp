"""
超快速抢单服务 - 优化版
优化策略：
1. 预加载验证码
2. 并行处理
3. 连接池优化
4. 减少延迟
"""
import time
import threading
from queue import Queue
import asyncio
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class UltraFastGrabService:
    def __init__(self, token_data, log_callback):
        self.token_data = token_data
        self.log = log_callback
        self.api_base_url = "https://dysh.dyswl.com"
        
        # 超快速配置
        self.check_interval = 0.1  # 100ms检查一次
        self.max_workers = 10  # 10个并发线程
        self.category_id = "131"
        
        # 优化的连接池
        self.session = self._create_optimized_session()
        
        # 预加载缓存
        self.verification_cache = Queue(maxsize=20)
        self.cache_thread = None
        
        # 并发执行器
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        
        # AI服务器（预连接）
        self.ai_session = self._create_ai_session()
        self.ai_url = "http://154.219.127.13:8889/api/verify"
        
        self.running = False
        
    def _create_optimized_session(self):
        """创建优化的HTTP会话"""
        session = requests.Session()
        
        # 连接池优化
        adapter = HTTPAdapter(
            pool_connections=50,  # 连接池大小
            pool_maxsize=50,
            max_retries=Retry(total=1, backoff_factor=0.1)
        )
        session.mount('https://', adapter)
        session.mount('http://', adapter)
        
        # Headers
        session.headers.update({
            'Authorization': f"Bearer {self.token_data.get('token', '')}",
            'User-Agent': 'Mozilla/5.0 (Android 12)',
            'club-id': str(self.token_data.get('club_id', '')),
            'role-id': str(self.token_data.get('role_id', '')),
            'tenant-id': str(self.token_data.get('tenant_id', '')),
            'Connection': 'keep-alive',
            'Accept-Encoding': 'gzip, deflate',
        })
        
        # 预热连接
        try:
            session.get(f"{self.api_base_url}/health", timeout=1)
        except:
            pass
            
        return session
    
    def _create_ai_session(self):
        """创建AI服务器会话"""
        session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=20,
            pool_maxsize=20,
            max_retries=Retry(total=0)  # 不重试，快速失败
        )
        session.mount('http://', adapter)
        
        # 预热连接
        try:
            session.get("http://154.219.127.13:8889/health", timeout=1)
        except:
            pass
            
        return session
    
    def _preload_verifications(self):
        """预加载验证码（后台线程）"""
        while self.running:
            try:
                if self.verification_cache.qsize() < 10:
                    # 获取验证
                    import uuid
                    challenge = str(uuid.uuid4())
                    
                    response = self.ai_session.post(
                        self.ai_url,
                        json={
                            'captcha_id': '045e2c229998a88721e32a763bc0f7b8',
                            'challenge': challenge,
                            'threshold': 0.7
                        },
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        if result.get('success'):
                            # 缓存结果
                            self.verification_cache.put({
                                'lot_number': result.get('lot_number'),
                                'captcha_output': result.get('captcha_output'),
                                'pass_token': result.get('pass_token'),
                                'gen_time': result.get('gen_time'),
                                'cached_at': time.time()
                            })
                            self.log(f"[CACHE] 预加载验证 {self.verification_cache.qsize()}/10")
                
                time.sleep(1)  # 每秒检查一次
                
            except Exception as e:
                self.log(f"[CACHE] 预加载失败: {e}")
                time.sleep(2)
    
    def _get_verification(self, order_id):
        """获取验证（优先使用缓存）"""
        # 尝试从缓存获取
        if not self.verification_cache.empty():
            try:
                cached = self.verification_cache.get_nowait()
                # 检查是否过期（30秒）
                if time.time() - cached['cached_at'] < 30:
                    self.log("[VERIFY] 使用缓存验证 ⚡")
                    return cached
            except:
                pass
        
        # 缓存未命中，实时获取
        self.log("[VERIFY] 实时获取验证...")
        start = time.time()
        
        import uuid
        challenge = str(uuid.uuid4())
        
        try:
            response = self.ai_session.post(
                self.ai_url,
                json={
                    'captcha_id': '045e2c229998a88721e32a763bc0f7b8',
                    'challenge': challenge,
                    'threshold': 0.7
                },
                timeout=3  # 3秒超时
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    self.log(f"[VERIFY] 验证成功 ({(time.time()-start)*1000:.0f}ms)")
                    return {
                        'lot_number': result.get('lot_number'),
                        'captcha_output': result.get('captcha_output'),
                        'pass_token': result.get('pass_token'),
                        'gen_time': result.get('gen_time')
                    }
        except Exception as e:
            self.log(f"[VERIFY] 失败: {e}")
        
        return None
    
    def _grab_order_ultra_fast(self, order):
        """超快速抢单"""
        order_id = order.get('orderNo') or order.get('id')
        
        try:
            # 获取验证（缓存或实时）
            start = time.time()
            verification = self._get_verification(order_id)
            
            if not verification:
                self.log(f"[SKIP] {order_id}: 验证失败")
                return False
            
            verify_time = (time.time() - start) * 1000
            
            # 构建请求
            gee_dto = {
                'lotNumber': verification['lot_number'],
                'captchaOutput': verification['captcha_output'],
                'passToken': verification['pass_token'],
                'genTime': str(verification['gen_time']),
                'captchaId': '045e2c229998a88721e32a763bc0f7b8',
                'captchaKeyType': 'dlVerify'
            }
            
            payload = {
                'orderId': int(order_id) if isinstance(order_id, str) else order_id,
                'geeDto': gee_dto
            }
            
            # 发送抢单请求
            url = f"{self.api_base_url}/gate/app-api/club/order/grabAnOrder/v1"
            
            grab_start = time.time()
            response = self.session.post(
                url, 
                json=payload,
                timeout=2  # 2秒超时
            )
            grab_time = (time.time() - grab_start) * 1000
            
            total_time = (time.time() - start) * 1000
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') in [0, 200]:
                    self.log(f"✅ 抢单成功！订单{order_id} (总耗时: {total_time:.0f}ms)")
                    return True
                else:
                    self.log(f"❌ 订单{order_id}: {result.get('msg')} ({total_time:.0f}ms)")
            else:
                self.log(f"❌ HTTP {response.status_code} ({total_time:.0f}ms)")
                
        except Exception as e:
            self.log(f"[ERROR] {order_id}: {e}")
        
        return False
    
    def _check_orders_ultra_fast(self):
        """超快速检查订单"""
        url = f"{self.api_base_url}/gate/app-api/club/order/getOrderPoolsList"
        params = {
            'productCategoryParentId': self.category_id,
            'userServerAreaId': ''
        }
        
        try:
            response = self.session.get(
                url, 
                params=params,
                timeout=1  # 1秒超时
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') in [0, 200]:
                    orders = data.get('data', {}).get('dataList', [])
                    return orders
        except:
            pass
        
        return []
    
    def _monitor_loop(self):
        """监控循环（超快速）"""
        self.log("⚡ 超快速模式启动")
        self.log(f"  检查间隔: {self.check_interval*1000:.0f}ms")
        self.log(f"  并发线程: {self.max_workers}")
        self.log(f"  预加载缓存: 启用")
        
        processed_orders = set()
        futures = []
        
        while self.running:
            try:
                # 超快速检查
                orders = self._check_orders_ultra_fast()
                
                if orders:
                    # 找出新订单
                    new_orders = []
                    for order in orders:
                        order_id = order.get('orderNo') or order.get('id')
                        if order_id and order_id not in processed_orders:
                            new_orders.append(order)
                            processed_orders.add(order_id)
                    
                    if new_orders:
                        self.log(f"[NEW] 发现 {len(new_orders)} 个新订单")
                        
                        # 并发抢单
                        for order in new_orders[:5]:  # 最多同时抢5个
                            future = self.executor.submit(
                                self._grab_order_ultra_fast, 
                                order
                            )
                            futures.append(future)
                        
                        # 清理完成的futures
                        futures = [f for f in futures if not f.done()]
                
                # 清理旧订单ID（防止内存泄漏）
                if len(processed_orders) > 1000:
                    processed_orders.clear()
                
                # 超短延迟
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.log(f"[ERROR] 监控异常: {e}")
                time.sleep(1)
    
    def start(self):
        """启动超快速抢单"""
        if self.running:
            return
        
        self.running = True
        
        # 启动预加载线程
        self.cache_thread = threading.Thread(
            target=self._preload_verifications,
            daemon=True
        )
        self.cache_thread.start()
        
        # 启动监控线程
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )
        self.monitor_thread.start()
        
        self.log("🚀 超快速抢单服务已启动")
    
    def stop(self):
        """停止服务"""
        self.running = False
        self.executor.shutdown(wait=False)
        self.session.close()
        self.ai_session.close()
        self.log("⏹️ 超快速抢单服务已停止")
