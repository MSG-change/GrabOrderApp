# -*- coding:utf-8 -*-
# @Time     : 2025/11/7 11:58
# @Author   : 或与非
# @Email    : anf57@hotmail.com

import hashlib
import json
import random
import string
from waitress import serve
from flask import Flask, request
import execjs
import os
app = Flask(__name__)

js_file = os.path.join(os.getcwd(), "gcaptcha4_click.js")
with open(js_file, "r", encoding="utf-8") as f:
    js_code = f.read()
    ctll = execjs.compile(js_code)


# 九宫格 输入 序号1-9 返回坐标数组
def num_to_coordinate(num_str):
    num_list = num_str.strip().split(",")
    num_list = [int(num)+1 for num in num_list]
    return [[(int(num) - 1) // 3 + 1, (int(num) - 1) % 3 + 1] for num in num_list]

def get_request_data():
    if request.form:
        # 处理表单提交的数据，支持多个相同参数的键
        form_data = {}
        for key in request.form.keys():
            values = request.form.getlist(key)  # 处理列表形式的参数
            form_data[key] = values if len(values) > 1 else values[0]  # 如果只有一个值，则不返回列表
        request_data = form_data
    else:
        # 处理 application/json 提交的数据
        request_data = json.loads(request.data or "{}")
    # print(f"请求数据:\n{request_data}")
    return request_data

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

def getw(lot_number, captcha_id, version, bits, datetime, hashfunc, pic_index):
    pow_msg, pow_sign = pow_calculate(lot_number, captcha_id, hashfunc, version, bits, datetime, "")
    userresponse = num_to_coordinate(pic_index)
    return ctll.call("get_click_w", lot_number, pow_msg, pow_sign, userresponse)


@app.route("/captcha/w/", methods=["POST"])
def hstd_space():
    result = get_request_data()
    print(result)
    lot_number = result.get("lot_number")
    captcha_id = result.get("captcha_id")
    version = result.get("version")
    bits_ = int(result.get("bits"))
    datetime = result.get("datetime")
    hashfunc = result.get("hashfunc")
    pic_index = result.get("pic_index")
    result = {"w": getw(lot_number, captcha_id, version, bits_, datetime, hashfunc, pic_index)}
    print(result)
    return result

if __name__ == '__main__':
    print(f"API: http://127.0.0.1:9088/captcha/w/")
    serve(app=app, host="0.0.0.0", port=9088, threads=30)
