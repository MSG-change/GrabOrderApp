#!/bin/bash
# Android日志查看脚本（支持MuMu模拟器）

echo "=========================================="
echo "🔍 Android应用日志查看工具"
echo "=========================================="
echo ""

# 检查adb是否可用
if ! command -v adb &> /dev/null; then
    echo "❌ 错误: adb 未找到"
    echo "   请安装 Android SDK Platform Tools"
    echo "   下载地址: https://developer.android.com/studio/releases/platform-tools"
    exit 1
fi

# MuMu模拟器端口（可配置）
MUMU_PORT=${MUMU_PORT:-5555}
MUMU_HOST="127.0.0.1"

# 检查设备连接
echo "📱 检查设备连接..."
DEVICES=$(adb devices | grep -v "List" | grep "device$" | wc -l)

if [ "$DEVICES" -eq 0 ]; then
    echo "⚠️  未找到已连接的设备，尝试连接MuMu模拟器..."
    echo "   连接地址: ${MUMU_HOST}:${MUMU_PORT}"
    
    # 尝试连接MuMu模拟器
    adb connect ${MUMU_HOST}:${MUMU_PORT} 2>&1 | while read line; do
        echo "   $line"
    done
    
    # 等待连接
    sleep 2
    
    # 再次检查设备
    DEVICES=$(adb devices | grep -v "List" | grep "device$" | wc -l)
    
    if [ "$DEVICES" -eq 0 ]; then
        echo ""
        echo "❌ 错误: 无法连接到设备"
        echo ""
        echo "🔧 解决方案:"
        echo "   1. 如果是MuMu模拟器:"
        echo "      - 确保MuMu模拟器已启动"
        echo "      - 在MuMu设置中开启USB调试"
        echo "      - 手动连接: adb connect ${MUMU_HOST}:${MUMU_PORT}"
        echo ""
        echo "   2. 如果是真实手机:"
        echo "      - 确保手机已通过USB连接到电脑"
        echo "      - 已开启USB调试"
        echo "      - 已在手机上授权USB调试"
        echo ""
        echo "   3. 查看所有设备:"
        echo "      adb devices"
        echo ""
        exit 1
    fi
fi

echo "✅ 找到 $DEVICES 个设备"
adb devices
echo ""

# 清空日志
echo "🧹 清空旧日志..."
adb logcat -c

echo ""
echo "=========================================="
echo "📋 开始实时显示日志"
echo "=========================================="
echo "按 Ctrl+C 停止"
echo ""
echo "正在过滤: GrabOrder | Python | Kivy | Error | Exception"
echo ""

# 实时显示日志（过滤关键信息）
adb logcat | grep --line-buffered -i "graborder\|python\|kivy\|error\|exception\|crash\|fatal" | while read line; do
    # 高亮错误
    if echo "$line" | grep -qi "error\|exception\|crash\|fatal"; then
        echo -e "\033[31m$line\033[0m"  # 红色
    elif echo "$line" | grep -qi "warning"; then
        echo -e "\033[33m$line\033[0m"  # 黄色
    else
        echo "$line"
    fi
done

