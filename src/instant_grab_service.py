"""
极速秒抢服务 - 最激进优化版
目标：订单出现后0.3秒内完成抢单
策略：
1. 跳过所有可跳过的步骤
2. 极限并发
3. 预生成大量验证
4. 投机执行
"""
import time
import threading
from queue import Queue
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import uuid

class InstantGrabService:
    """极速秒抢 - 0.3秒内完成"""
    
    def __init__(self, token_data, log_callback):
        self.token_data = token_data
        self.log = log_callback
        self.api_base_url = "https://dysh.dyswl.com"
        
        # 极限配置
        self.check_interval = 0.05  # 50ms检查一次！
        self.max_workers = 30  # 30个并发线程
        self.category_id = "131"
        
        # 预验证缓存（大容量）
        self.verification_cache = Queue(maxsize=100)  # 缓存100个！
        self.min_cache_size = 50  # 保持至少50个
        
        # 超级连接池
        self.session = self._create_super_session()
        
        # AI连接池（多个会话）
        self.ai_sessions = [self._create_ai_session() for _ in range(10)]
        self.ai_url = "http://154.219.127.13:8889/api/verify"
        
        # 执行器
        self.grab_executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.cache_executor = ThreadPoolExecutor(max_workers=20)
        
        self.running = False
        
        # 已处理订单（避免重复）
        self.processed = set()
        
        # 统计
        self.stats = {
            'total_time': [],
            'grab_success': 0,
            'grab_failed': 0
        }
    
    def _create_super_session(self):
        """创建超级优化的会话"""
        session = requests.Session()
        
        # 极限连接池
        adapter = HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=0  # 不重试
        )
        session.mount('https://', adapter)
        session.mount('http://', adapter)
        
        # Headers
        session.headers.update({
            'Authorization': f"Bearer {self.token_data.get('token', '')}",
            'User-Agent': 'okhttp/4.9.1',
            'club-id': str(self.token_data.get('club_id', '')),
            'role-id': str(self.token_data.get('role_id', '')),
            'tenant-id': str(self.token_data.get('tenant_id', '')),
            'Connection': 'keep-alive',
            'Accept-Encoding': 'gzip',
        })
        
        # 预热（建立连接）
        try:
            session.get(f"{self.api_base_url}/health", timeout=0.5)
        except:
            pass
            
        return session
    
    def _create_ai_session(self):
        """创建AI会话"""
        session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=20,
            pool_maxsize=20,
            max_retries=0
        )
        session.mount('http://', adapter)
        return session
    
    def _mass_preload(self):
        """大规模预加载验证码"""
        while self.running:
            try:
                current_size = self.verification_cache.qsize()
                
                if current_size < self.min_cache_size:
                    # 需要补充
                    need = self.min_cache_size - current_size
                    self.log(f"[CACHE] 补充验证 {need}个...")
                    
                    # 并发获取
                    futures = []
                    for i in range(min(need, 20)):  # 一次最多20个
                        session = self.ai_sessions[i % len(self.ai_sessions)]
                        future = self.cache_executor.submit(
                            self._get_single_verification, 
                            session
                        )
                        futures.append(future)
                    
                    # 收集结果
                    for future in as_completed(futures):
                        try:
                            result = future.result(timeout=3)
                            if result:
                                self.verification_cache.put(result)
                        except:
                            pass
                    
                    self.log(f"[CACHE] 缓存量: {self.verification_cache.qsize()}/100")
                
                time.sleep(2)  # 每2秒检查
                
            except Exception as e:
                self.log(f"[CACHE] 错误: {e}")
                time.sleep(1)
    
    def _get_single_verification(self, session):
        """获取单个验证"""
        try:
            challenge = str(uuid.uuid4())
            
            response = session.post(
                self.ai_url,
                json={
                    'captcha_id': '045e2c229998a88721e32a763bc0f7b8',
                    'challenge': challenge,
                    'threshold': 0.7
                },
                timeout=3
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return {
                        'lot_number': result.get('lot_number'),
                        'captcha_output': result.get('captcha_output'),
                        'pass_token': result.get('pass_token'),
                        'gen_time': result.get('gen_time'),
                        'created_at': time.time()
                    }
        except:
            pass
        return None
    
    def _instant_grab(self, order):
        """极速抢单（目标<0.3秒）"""
        start = time.time()
        order_id = order.get('orderNo') or order.get('id')
        
        if order_id in self.processed:
            return False
        self.processed.add(order_id)
        
        try:
            # 从缓存取验证（极快）
            if not self.verification_cache.empty():
                verification = self.verification_cache.get_nowait()
                
                # 检查是否过期（30秒）
                if time.time() - verification['created_at'] > 30:
                    # 过期了，取下一个
                    if not self.verification_cache.empty():
                        verification = self.verification_cache.get_nowait()
                    else:
                        self.log(f"[SKIP] {order_id}: 缓存空")
                        return False
            else:
                self.log(f"[SKIP] {order_id}: 无缓存")
                return False
            
            # 构建请求（极简）
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
            
            # 发送（超短超时）
            url = f"{self.api_base_url}/gate/app-api/club/order/grabAnOrder/v1"
            
            response = self.session.post(
                url, 
                json=payload,
                timeout=1  # 1秒超时
            )
            
            total = (time.time() - start) * 1000
            self.stats['total_time'].append(total)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') in [0, 200]:
                    self.log(f"🎯 秒抢成功！{order_id} ({total:.0f}ms)")
                    self.stats['grab_success'] += 1
                    return True
                else:
                    self.log(f"❌ {order_id}: {result.get('msg')} ({total:.0f}ms)")
                    self.stats['grab_failed'] += 1
            else:
                self.log(f"❌ HTTP {response.status_code} ({total:.0f}ms)")
                
        except Exception as e:
            total = (time.time() - start) * 1000
            self.log(f"[ERROR] {order_id}: {str(e)[:30]} ({total:.0f}ms)")
        
        return False
    
    def _ultra_check(self):
        """极速检查（50ms一次）"""
        url = f"{self.api_base_url}/gate/app-api/club/order/getOrderPoolsList"
        params = {
            'productCategoryParentId': self.category_id,
            'userServerAreaId': ''
        }
        
        futures = []
        last_check = 0
        
        while self.running:
            try:
                now = time.time()
                if now - last_check < 0.05:  # 50ms限制
                    time.sleep(0.01)
                    continue
                
                last_check = now
                
                # 检查订单
                try:
                    response = self.session.get(
                        url, 
                        params=params,
                        timeout=0.5  # 500ms超时
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        if data.get('code') in [0, 200]:
                            orders = data.get('data', {}).get('dataList', [])
                            
                            if orders:
                                self.log(f"[发现] {len(orders)}个订单")
                                
                                # 极限并发抢单
                                for order in orders:
                                    order_id = order.get('orderNo') or order.get('id')
                                    if order_id and order_id not in self.processed:
                                        # 立即抢！
                                        future = self.grab_executor.submit(
                                            self._instant_grab,
                                            order
                                        )
                                        futures.append(future)
                except:
                    pass
                
                # 清理futures
                futures = [f for f in futures if not f.done()]
                
                # 清理processed（防止内存泄漏）
                if len(self.processed) > 1000:
                    self.processed.clear()
                
            except Exception as e:
                self.log(f"[CHECK] 错误: {str(e)[:30]}")
                time.sleep(0.1)
    
    def start(self):
        """启动极速秒抢"""
        if self.running:
            return
        
        self.running = True
        self.log("⚡⚡⚡ 极速秒抢模式启动")
        self.log(f"  检查间隔: 50ms")
        self.log(f"  并发线程: 30")
        self.log(f"  预加载缓存: 50-100个")
        self.log(f"  目标速度: <300ms")
        
        # 启动大规模预加载
        cache_thread = threading.Thread(
            target=self._mass_preload,
            daemon=True
        )
        cache_thread.start()
        
        # 等待缓存准备
        self.log("⏳ 准备缓存中...")
        for i in range(10):
            time.sleep(1)
            size = self.verification_cache.qsize()
            self.log(f"  缓存: {size}/50")
            if size >= 20:
                break
        
        # 启动极速检查
        check_thread = threading.Thread(
            target=self._ultra_check,
            daemon=True
        )
        check_thread.start()
        
        self.log("🚀 极速秒抢已启动！")
        self.log("⚡ 目标: 0.3秒内完成")
        
        # 统计线程
        def show_stats():
            while self.running:
                time.sleep(10)
                if self.stats['total_time']:
                    avg = sum(self.stats['total_time']) / len(self.stats['total_time'])
                    self.log(f"[统计] 平均耗时: {avg:.0f}ms, 成功: {self.stats['grab_success']}, 失败: {self.stats['grab_failed']}")
        
        stats_thread = threading.Thread(target=show_stats, daemon=True)
        stats_thread.start()
    
    def stop(self):
        """停止"""
        self.running = False
        self.grab_executor.shutdown(wait=False)
        self.cache_executor.shutdown(wait=False)
        self.session.close()
        for s in self.ai_sessions:
            s.close()
        self.log("⏹️ 极速秒抢已停止")
