#!/data/data/com.termux/files/usr/bin/bash
# Termux快速配置脚本 - 使用国内镜像源

echo "🚀 Termux 快速配置（国内镜像源）"
echo "=================================="

# 1. 更换Termux镜像源（清华源）
echo "📦 配置清华源..."
sed -i 's@^\(deb.*stable main\)$@#\1\ndeb https://mirrors.tuna.tsinghua.edu.cn/termux/termux-packages-24 stable main@' $PREFIX/etc/apt/sources.list
sed -i 's@^\(deb.*games stable\)$@#\1\ndeb https://mirrors.tuna.tsinghua.edu.cn/termux/game-packages-24 games stable@' $PREFIX/etc/apt/sources.list.d/game.list
sed -i 's@^\(deb.*science stable\)$@#\1\ndeb https://mirrors.tuna.tsinghua.edu.cn/termux/science-packages-24 science stable@' $PREFIX/etc/apt/sources.list.d/science.list

# 更新包列表
pkg update -y

# 2. 安装基础包
echo "📦 安装Python和Git..."
pkg install python git wget -y

# 3. 配置pip镜像源（阿里云）
echo "🔧 配置pip阿里云镜像..."
mkdir -p ~/.pip
cat > ~/.pip/pip.conf << EOF
[global]
index-url = https://mirrors.aliyun.com/pypi/simple/
trusted-host = mirrors.aliyun.com
EOF

# 4. 升级pip
python -m pip install --upgrade pip

# 5. 安装Python包（使用阿里云镜像）
echo "📦 安装Python依赖..."
pip install pillow requests numpy -i https://mirrors.aliyun.com/pypi/simple/

echo "✅ 基础环境配置完成！"
