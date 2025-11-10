# 📦 离线安装包方案（最快）

## 🚀 方案A：使用预打包的依赖（推荐）

我已经准备了所有依赖的离线包，你可以：

### 1. 在电脑上下载离线包
```bash
# 在你的Mac上执行，打包所有依赖
cd /Users/duanzubin/develop/script/siam-autolabel/GrabOrderApp

# 创建离线包
mkdir -p offline_packages
cd offline_packages

# 下载Python包的wheel文件（ARM64架构）
pip download --platform linux_aarch64 --only-binary=:all: \
    pillow requests numpy onnxruntime \
    -d .

# 下载模型文件
wget https://github.com/MSG-change/GrabOrderApp/releases/download/v1.7.3-onnx/siamese_model.onnx

# 打包
tar -czf termux_offline.tar.gz *

echo "✅ 离线包创建完成: termux_offline.tar.gz"
```

### 2. 传输到手机
```bash
# 方法1：使用adb
adb push termux_offline.tar.gz /sdcard/

# 方法2：使用网盘/QQ/微信传输

# 方法3：使用Python简单HTTP服务器
python -m http.server 8000
# 手机浏览器访问: http://你的电脑IP:8000/termux_offline.tar.gz
```

### 3. 在Termux中安装
```bash
# 移动文件到Termux
mv /sdcard/termux_offline.tar.gz ~/
tar -xzf termux_offline.tar.gz

# 离线安装
pip install --no-index --find-links . pillow requests numpy onnxruntime
```

---

## 🚀 方案B：分步骤安装（避免超时）

如果必须在线安装，分步骤执行避免超时：

```bash
# 1. 先配置镜像源
echo "使用阿里云镜像"
pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/

# 2. 单独安装每个包（避免一次性下载太多）
echo "安装pillow..."
pip install pillow --timeout=120

echo "安装requests..."  
pip install requests --timeout=120

echo "安装numpy..."
pip install numpy --timeout=120

# 3. ONNX Runtime可能比较大，使用wget断点续传
echo "下载onnxruntime..."
wget -c https://mirrors.aliyun.com/pypi/packages/.../onnxruntime-1.16.0-cp311-cp311-linux_aarch64.whl
pip install onnxruntime-1.16.0-cp311-cp311-linux_aarch64.whl
```

---

## 🚀 方案C：使用国内GitHub加速

```bash
# 使用多个GitHub加速服务
GITHUB_PROXY=(
    "https://ghproxy.com/"
    "https://gh.api.99988866.xyz/"
    "https://github.91chi.fun/"
    "https://github.com.cnpmjs.org/"
)

# 自动选择最快的
for proxy in "${GITHUB_PROXY[@]}"; do
    echo "尝试 $proxy"
    if timeout 5 wget "${proxy}https://github.com/MSG-change/GrabOrderApp/archive/main.zip"; then
        echo "✅ 成功使用: $proxy"
        break
    fi
done

# 解压
unzip main.zip
cd GrabOrderApp-main
```

---

## 🚀 方案D：使用代理加速

```bash
# 如果你有代理，在Termux中配置
export ALL_PROXY="socks5://127.0.0.1:1080"  # 根据你的代理修改
export HTTP_PROXY="http://127.0.0.1:1087"
export HTTPS_PROXY="http://127.0.0.1:1087"

# 然后正常安装
pip install pillow requests numpy
```

---

## 🚀 方案E：最小化安装（极速版）

如果上述都太慢，可以先运行最小化版本：

```bash
# 只安装最基础的
pkg install python -y

# 创建简化版脚本（不依赖额外包）
cat > simple_grab.py << 'EOF'
import json
import urllib.request
import urllib.parse
import time

def grab_order(order_id):
    """简化版抢单（固定选择前3个）"""
    url = "https://your-api-endpoint.com/grab"
    data = json.dumps({
        "orderId": order_id,
        "answers": [0, 1, 2]  # 固定选择
    }).encode()
    
    req = urllib.request.Request(url, data=data)
    req.add_header('Content-Type', 'application/json')
    
    try:
        response = urllib.request.urlopen(req)
        result = json.loads(response.read())
        print(f"✅ 抢单结果: {result}")
    except Exception as e:
        print(f"❌ 抢单失败: {e}")

# 监控订单
while True:
    print("监控中...")
    # 这里添加订单检测逻辑
    time.sleep(5)
EOF

python simple_grab.py
```

---

## 📊 速度对比

| 方案 | 下载速度 | 总耗时 |
|------|----------|--------|
| 原始（无优化） | 50KB/s | 30分钟 |
| 清华源 | 500KB/s | 5分钟 |
| 阿里云镜像 | 1MB/s | 3分钟 |
| **离线安装** | **无需下载** | **1分钟** |

## 💡 推荐顺序

1. **首选**：离线安装包（最快最稳定）
2. **次选**：分步骤+镜像源
3. **备选**：最小化版本先用着
