# -*- coding:utf-8 -*-
# @Time     : 2025/10/19 13:54
# @Author   : 或与非
# @Email    : anf57@hotmail.com
import json
import time
import os
import hashlib
import uuid
import random
import string
from urllib.request import urlretrieve
import execjs
import requests

# 用于 生成 sign参数
def guid():
    """生成一个随机 GUID 字符串"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

# md5 sha1 sha256
def hash_function(s, algo):
    """根据指定的算法进行哈希计算"""
    if algo == "md5":
        return hashlib.md5(s.encode()).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(s.encode()).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(s.encode()).hexdigest()
    return None

# 生成 pow 参数
def pow_calculate(e, t, s, n, i, o, r):
    """
    :param e:lotNumber
    :param t: captcha_id
    :param s: ["powDetail"][hashfunc]
    :param n: ["powDetail"][version]
    :param i: ["powDetail"]["bits"]
    :param o: ["powDetail"]["datetime"]
    :param r: ""
    :return:
    """
    """PoW 计算"""
    _ = i % 4
    u = int(i / 4)
    c = '0' * (u + 1)  # 创建一个由 '0' 组成的字符串，长度为 u + 1
    h = f"{n}|{i}|{s}|{o}|{t}|{e}|{r}|"

    while True:
        l = guid()  # 随机生成一个 GUID
        p = h + l  # 将 GUID 和其他参数拼接成字符串
        f = hash_function(p, s)  # 使用指定的哈希算法进行哈希计算

        if f is None:
            raise ValueError("Invalid hash function")

        if _ == 0:
            if f.startswith(c):  # 如果哈希值以指定数量的 '0' 开头
                return h + l, f
                return {"pow_msg": h + l, "pow_sign": f}
        elif f.startswith(c):
            g = int(f[u], 16)  # 提取哈希值中第 u 个字符
            d = {1: 7, 2: 3, 3: 1}.get(_, None)

            if d is not None and g <= d:  # 如果满足条件
                return h + l, f
                return {"pow_msg": h + l, "pow_sign": f}

def num_to_coordinate(num_str):
    num_list = num_str.strip().split(",")
    num_list = [int(num)+1 for num in num_list]
    return [[(int(num) - 1) // 3 + 1, (int(num) - 1) % 3 + 1] for num in num_list]

PATH_WORK = os.getcwd()
js_file = os.path.join(PATH_WORK, "gcaptcha4_click.js")
with open(js_file, "r", encoding="utf-8") as f:
    js_code = f.read()
    ctll = execjs.compile(js_code)

def get_coord():
    url = "https://unhasted-cruciferous-azaria.ngrok-free.dev/api/v1/recognize"
    headres = {"Content-Type": "application/json"}
    resp = requests.post(url, json={"captcha_id": "045e2c229998a88721e32a763bc0f7b8"}, headers=headres).json()
    print(resp)

class JiYan:
    def __init__(self, proxy_ip="", captcha_id="045e2c229998a88721e32a763bc0f7b8",trust_env=False,):
        self.session = requests.session()
        self.session.trust_env = trust_env
        self.session.proxies = self._build_proxies(proxy_ip)
        self.proxy_ip = proxy_ip
        self.captcha_id = captcha_id
        self.load_url = 'https://gcaptcha4.geetest.com/load'
        self.verify_url = 'https://gcaptcha4.geetest.com/verify'
        self.static_server = "https://static.geetest.com/"
        self.lot_number = None
        self.payload = None
        self.process_token = None
        self.ques = []
        self.pow_detail = None
        self.headers = {
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "zh-CN,zh;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "Referer": "https://www.geetest.com/",
            "sec-ch-ua": "^\\^Google",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "^\\^Windows^^",
            "sec-fetch-dest": "script",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
        }
        self.challenge = str(uuid.uuid4())


    @staticmethod
    def _build_proxies(proxy_ip: str):
        """根据输入构造 requests 可用的代理格式"""
        if not proxy_ip:
            return None  # 不使用代理时返回 None 更规范

        # 若已经包含协议 例如 http://1.2.3.4:8080 或 socks5://x.x.x.x:1080
        if proxy_ip.startswith(("http://", "socks5://", "https://")):
            proxy = proxy_ip
        else:  # 无协议则默认 http
            proxy = f"http://{proxy_ip}"

        return {"http": proxy, "https": proxy}

    def geetest_load(self):
        params = {
            "captcha_id": self.captcha_id,
            "challenge": self.challenge,
            # "client_type": "web",
            "client_type": "android",
            "lang": "zh",
            "callback": "geetest_" + str(int(float(time.time()) * 1000))
        }
        response = self.session.get(url=self.load_url, headers=self.headers, params=params)
        result = json.loads(response.text[22:-1])['data']

        self.lot_number = result.get('lot_number')
        self.payload = result.get('payload')
        self.process_token = result.get('process_token')

        pow_detail = result.get('pow_detail')
        self.pow_detail = pow_detail
        self.pow = "|".join([str(pow_detail.get('version')), str(pow_detail.get('bits')), pow_detail.get('hashfunc'),
                             pow_detail.get('datetime'), self.captcha_id, self.lot_number])
        imgs = f"{self.static_server}{result.get('imgs')}"
        urlretrieve(imgs, "jy_nine_bg.jpg")
        urlretrieve(f"{self.static_server}{result.get('ques')[0]}", "jy_nine_fg.jpg")

    def geetest_verify(self, w):
        params = {
            "callback": "geetest_" + str(int(float(time.time()) * 1000)),
            "captcha_id": self.captcha_id,
            # "client_type": "web",
            "client_type": "android",
            "lot_number": self.lot_number,
            "payload": self.payload,
            "process_token": self.process_token,
            "payload_protocol": "1",
            "pt": "1",
            "w": w
        }
        response = self.session.get(url=self.verify_url, headers=self.headers, params=params)
        result = json.loads(response.text[22:-1])
        verify_data = result.get('data', {})
        data_result = verify_data.get('result')
        if data_result == 'success':
            print(f"\t验证成功:{result}")
        else:
            print(f"\t验证失败请重试:{result}")
        return verify_data

    def generate_w(self, use_api=False):
        version = self.pow_detail.get("version")
        bits = self.pow_detail.get("bits")
        datetime = self.pow_detail.get("datetime")
        hashfunc = self.pow_detail.get("hashfunc")
        pow_msg, pow_sign = pow_calculate(self.lot_number, self.captcha_id, hashfunc, version, bits, datetime, "")
        if use_api:
            data = {
                "lot_number": self.lot_number,
                "captcha_id": self.captcha_id,
                "version": version,
                "bits": bits,
                "datetime": datetime,
                "hashfunc": hashfunc,
                "pic_index": input("请输入图片的序号0-8(逗号隔开):"),
            }
            w = requests.post("http://122.51.11.20:9088/captcha/w/", json=data).json().get("w")
            print(w)
        else:
            userresponse = num_to_coordinate(input("请输入图片的序号0-8(逗号隔开):"))
            w = ctll.call("get_click_w", self.lot_number, pow_msg, pow_sign, userresponse)
        return w

    def run(self,):
        # 1 获取验证码信息
        self.geetest_load()
        # 2 获取 w 参数
        w = self.generate_w()
        if not w:
            return {}
        # 3 进行验证
        verify_data = self.geetest_verify(w)

        return verify_data

if __name__ == '__main__':
    JiYan(captcha_id="045e2c229998a88721e32a763bc0f7b8").run()


