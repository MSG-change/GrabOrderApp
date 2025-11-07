# 🐳 Docker镜像加速配置

## 问题
```
docker: Error response from daemon: Get "https://registry-1.docker.io/v2/": context deadline exceeded
```

## 解决方案

### 方法1：配置Docker镜像加速（推荐）

#### 1. 打开Docker Desktop配置

```
Docker Desktop → Settings (齿轮图标) → Docker Engine
```

#### 2. 添加国内镜像源

在配置JSON中添加：

```json
{
  "registry-mirrors": [
    "https://docker.mirrors.sjtug.sjtu.edu.cn",
    "https://docker.nju.edu.cn",
    "https://mirror.baidubce.com"
  ]
}
```

**完整配置示例：**

```json
{
  "builder": {
    "gc": {
      "defaultKeepStorage": "20GB",
      "enabled": true
    }
  },
  "experimental": false,
  "registry-mirrors": [
    "https://docker.mirrors.sjtug.sjtu.edu.cn",
    "https://docker.nju.edu.cn",
    "https://mirror.baidubce.com"
  ]
}
```

#### 3. 应用并重启

1. 点击 **Apply & Restart**
2. 等待Docker重启完成

#### 4. 验证

```bash
docker info | grep -A 5 "Registry Mirrors"
```

---

### 方法2：使用代理

#### 如果您有VPN/代理：

```
Docker Desktop → Settings → Resources → Proxies

启用 Manual proxy configuration:
  Web Server (HTTP): http://127.0.0.1:7890
  Secure Web Server (HTTPS): http://127.0.0.1:7890
```

**注意：端口号根据您的代理软件调整**

---

### 方法3：预先下载镜像（最快）

```bash
# 使用国内镜像直接pull
docker pull registry.cn-hangzhou.aliyuncs.com/kivy/buildozer:latest

# 重命名为官方镜像名
docker tag registry.cn-hangzhou.aliyuncs.com/kivy/buildozer:latest kivy/buildozer:latest

# 再次构建
cd /Users/duanzubin/develop/script/siam-autolabel/GrabOrderApp
./docker_build.sh
```

---

## 📝 推荐步骤

1. **先配置镜像加速**（方法1）
2. **如果还是慢，开代理**（方法2）
3. **实在不行，用国内镜像**（方法3）

---

## ⚡ 快速命令

配置完成后，直接运行：

```bash
cd /Users/duanzubin/develop/script/siam-autolabel/GrabOrderApp
./docker_build.sh
```

