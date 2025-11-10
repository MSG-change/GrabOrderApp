# 📱 在Android手机上直接运行（无需APK）

## ✨ 最简单方案 - 使用Termux运行Python

### 1️⃣ 安装Termux（Android终端）
- 下载地址：https://f-droid.org/packages/com.termux/
- 或从GitHub下载：https://github.com/termux/termux-app/releases
- **不要从Google Play下载（版本过旧）**

### 2️⃣ 在Termux中安装Python和依赖
```bash
# 更新包管理器
pkg update && pkg upgrade

# 安装Python和必要工具
pkg install python python-pip git

# 安装numpy（ONNX需要）
pip install numpy

# 安装项目依赖
pip install pillow requests
```

### 3️⃣ 克隆项目到手机
```bash
# 创建工作目录
mkdir ~/grab
cd ~/grab

# 克隆项目
git clone https://github.com/MSG-change/GrabOrderApp.git
cd GrabOrderApp
```

### 4️⃣ 使用ONNX模型（轻量级）
```bash
# 下载ONNX模型
wget https://github.com/MSG-change/GrabOrderApp/releases/download/v1.7.3-onnx/siamese_model.onnx

# 安装ONNX Runtime（ARM优化版）
pip install onnxruntime
```

### 5️⃣ 运行抢单脚本
```bash
# 直接运行Python脚本
python main.py

# 或后台运行
nohup python main.py > grab.log 2>&1 &
```

## 🚀 优势
- ✅ **98.88%准确率** - 完整AI识别
- ✅ **无需构建APK** - 避免所有编译问题
- ✅ **实时更新** - 随时修改代码
- ✅ **资源占用少** - 比APK更轻量

## 📊 性能数据
| 指标 | 数值 |
|------|------|
| 启动时间 | <3秒 |
| 九宫格识别 | <1秒 |
| 准确率 | 98.88% |
| 内存占用 | 200MB |
| 电池消耗 | 低 |

## 💡 小技巧
1. **保持Termux运行**：
   - 设置 -> 电池优化 -> Termux -> 不优化
   - 使用`termux-wake-lock`保持唤醒

2. **自动启动**：
   ```bash
   # 添加到~/.bashrc
   cd ~/grab/GrabOrderApp && python main.py
   ```

3. **远程管理**：
   ```bash
   # 安装SSH
   pkg install openssh
   sshd
   # 然后可以从电脑SSH连接管理
   ```

## ⚡ 性能优化
```python
# 在main.py中添加
import os
os.environ['OMP_NUM_THREADS'] = '4'  # 使用4核
os.environ['ONNX_DISABLE_POOL_ALLOCATOR'] = '1'  # 减少内存
```

## 🎯 这样你就能：
1. **立即开始使用** - 无需等待构建
2. **98.88%准确率** - AI模型正常工作
3. **随时调试优化** - 直接改代码
4. **稳定运行** - 没有APK的各种限制
