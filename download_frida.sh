#!/bin/bash
# Frida Server 快速下载脚本（多镜像源）

FRIDA_VERSION="16.1.8"
ARCH="arm64"
FILENAME="frida-server-${FRIDA_VERSION}-android-${ARCH}.xz"
OUTPUT="assets/frida-server-${ARCH}.xz"

echo "========================================"
echo "📥 下载 Frida Server"
echo "========================================"
echo "版本: ${FRIDA_VERSION}"
echo "架构: ${ARCH}"
echo ""

# 创建 assets 目录
mkdir -p assets

# 定义多个下载源（按速度排序）
MIRRORS=(
    "https://ghproxy.com/https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FILENAME}"
    "https://kkgithub.com/frida/frida/releases/download/${FRIDA_VERSION}/${FILENAME}"
    "https://mirror.ghproxy.com/https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FILENAME}"
    "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FILENAME}"
)

# 尝试每个镜像源
for i in "${!MIRRORS[@]}"; do
    mirror="${MIRRORS[$i]}"
    echo "尝试镜像源 $((i+1))/${#MIRRORS[@]}"
    echo "URL: ${mirror}"
    echo ""
    
    # 使用 curl 下载（5分钟超时）
    if curl -L --max-time 300 --connect-timeout 10 -o "${OUTPUT}" "${mirror}"; then
        # 检查文件大小
        if [ -f "${OUTPUT}" ]; then
            size=$(stat -f%z "${OUTPUT}" 2>/dev/null || stat -c%s "${OUTPUT}" 2>/dev/null)
            if [ "$size" -gt 1000000 ]; then  # 大于 1MB
                echo ""
                echo "✅ 下载成功！"
                echo "文件大小: $(du -h ${OUTPUT} | cut -f1)"
                echo ""
                
                # 解压
                echo "📦 解压..."
                unxz "${OUTPUT}"
                
                extracted="${OUTPUT%.xz}"
                if [ -f "${extracted}" ]; then
                    echo "✅ 解压成功！"
                    echo "文件位置: ${extracted}"
                    
                    # 设置执行权限
                    chmod +x "${extracted}"
                    
                    echo ""
                    echo "========================================"
                    echo "🎉 完成！"
                    echo "========================================"
                    exit 0
                else
                    echo "❌ 解压失败"
                    rm -f "${OUTPUT}"
                fi
            else
                echo "⚠️  文件太小，可能下载失败"
                rm -f "${OUTPUT}"
            fi
        fi
    fi
    
    echo ""
    echo "❌ 镜像源 $((i+1)) 失败，尝试下一个..."
    echo ""
done

echo "========================================"
echo "❌ 所有镜像源都失败了"
echo "========================================"
echo ""
echo "手动下载方法："
echo "1. 浏览器打开："
echo "   https://github.com/frida/frida/releases/tag/${FRIDA_VERSION}"
echo ""
echo "2. 下载文件："
echo "   frida-server-${FRIDA_VERSION}-android-${ARCH}.xz"
echo ""
echo "3. 放到这个目录："
echo "   ${PWD}/assets/"
echo ""
echo "4. 解压："
echo "   unxz assets/${FILENAME}"
echo ""
exit 1



