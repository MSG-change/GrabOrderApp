#!/data/data/com.termux/files/usr/bin/bash
# Termux一键配置脚本 - 自动选择最快的源

echo "🚀 Termux 智能换源脚本"
echo "======================"

# 测试各个镜像源的速度
echo "🔍 测试镜像源速度..."

test_speed() {
    local url=$1
    local name=$2
    echo -n "   测试 $name..."
    if timeout 3 curl -s "$url" > /dev/null; then
        echo " ✅ 可用"
        return 0
    else
        echo " ❌ 超时"
        return 1
    fi
}

# 测试清华源
if test_speed "https://mirrors.tuna.tsinghua.edu.cn/termux/" "清华源"; then
    TERMUX_MIRROR="https://mirrors.tuna.tsinghua.edu.cn/termux"
# 测试北京外国语大学源
elif test_speed "https://mirrors.bfsu.edu.cn/termux/" "北外源"; then
    TERMUX_MIRROR="https://mirrors.bfsu.edu.cn/termux"
# 测试南京大学源
elif test_speed "https://mirror.nju.edu.cn/termux/" "南大源"; then
    TERMUX_MIRROR="https://mirror.nju.edu.cn/termux"
else
    echo "⚠️ 国内镜像源都不可用，使用官方源"
    TERMUX_MIRROR="https://packages.termux.org/apt"
fi

echo "✅ 使用镜像源: $TERMUX_MIRROR"

# 配置Termux源
echo "deb $TERMUX_MIRROR/termux-packages-24 stable main" > $PREFIX/etc/apt/sources.list

# 更新
echo "📦 更新软件包列表..."
apt update -y

# 安装必要软件
echo "📦 安装Python和Git..."
apt install -y python git wget

# 配置多个pip镜像源（自动选择最快的）
echo "🔧 配置pip镜像源..."
mkdir -p ~/.pip
cat > ~/.pip/pip.conf << EOF
[global]
index-url = https://mirrors.aliyun.com/pypi/simple/
extra-index-url = https://pypi.douban.com/simple/
                  https://pypi.tuna.tsinghua.edu.cn/simple/
trusted-host = mirrors.aliyun.com
               pypi.douban.com
               pypi.tuna.tsinghua.edu.cn
timeout = 60
EOF

echo "✅ 配置完成！"
