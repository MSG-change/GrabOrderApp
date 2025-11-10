#!/data/data/com.termux/files/usr/bin/bash
# 修复Termux中Pillow安装问题

echo "🔧 修复Pillow编译依赖..."

# 1. 安装所有必要的编译依赖
echo "📦 安装编译依赖..."
pkg update -y
pkg install -y \
    python \
    build-essential \
    libjpeg-turbo \
    libjpeg-turbo-static \
    libpng \
    libpng-static \
    freetype \
    freetype-static \
    zlib \
    zlib-static \
    libwebp \
    libwebp-static \
    libtiff \
    libtiff-static \
    littlecms \
    littlecms-static \
    openjpeg \
    openjpeg-static

# 2. 设置编译环境变量
echo "🔧 配置编译环境..."
export LDFLAGS="-L$PREFIX/lib"
export CPPFLAGS="-I$PREFIX/include"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"

# 3. 升级pip和setuptools
echo "📦 升级pip..."
pip install --upgrade pip setuptools wheel -i https://pypi.doubanio.com/simple/

# 4. 安装Pillow（使用缓存加速）
echo "📦 安装Pillow..."
pip install pillow \
    --no-cache-dir \
    --global-option="build_ext" \
    --global-option="--enable-zlib" \
    --global-option="--enable-jpeg" \
    --global-option="--enable-tiff" \
    --global-option="--enable-freetype" \
    --global-option="--enable-webp" \
    -i https://pypi.doubanio.com/simple/

# 5. 验证安装
echo "✅ 验证安装..."
python -c "
from PIL import Image
import PIL.features
print('✅ Pillow安装成功!')
print(f'   版本: {PIL.__version__}')
print('   支持格式:')
for feature in ['zlib', 'libjpeg', 'libtiff', 'freetype2', 'webp']:
    if PIL.features.check(feature):
        print(f'   ✅ {feature}')
"

echo "🎉 完成！"
