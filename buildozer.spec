[app]

# Application name (English for Kivy compatibility)
title = Grab Order Assistant

# 包名
package.name = graborder

# 包域名
package.domain = com.graborder

# 主程序入口
source.dir = .
source.entry_point = main.py
source.include_exts = py,png,jpg,kv,atlas,json,onnx,js,ttf,xz
source.include_patterns = assets/*,libs/*,src/*

# 版本号
version = 1.1.4

# 应用需求（Python 包）
# 完全移除numpy依赖（使用纯Python + PIL + Java ONNX Runtime）
# Android使用远程API生成W参数，不需要execjs
# ✅ frida库用于Hook和动态分析（Android环境使用frida而不是frida-tools更轻量）
# ARM64 Frida 支持 - 确保为目标架构编译
# Note: For MuMu emulator, Frida may have architecture issues, using file-based fallback
requirements = python3,kivy==2.2.1,pillow,requests,pyjnius,android

# Frida ARM64 specific configuration
android.p4a_whitelist =
android.p4a_blacklist =
android.add_grant_uri_permissions = True

# Ensure Frida is properly included
android.add_jars =
android.add_aars =
android.add_libs_aarch64 = libs/arm64-v8a/*.so
android.add_libs_armeabi_v7a = libs/armeabi-v7a/*.so

# Frida specific build flags
p4a.hook = p4a_hook.py
p4a.local_recipes =

# 图标和启动画面
#icon.filename = %(source.dir)s/assets/icon.png
#presplash.filename = %(source.dir)s/assets/presplash.png

# Android 权限
android.permissions = INTERNET,ACCESS_NETWORK_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE,SYSTEM_ALERT_WINDOW,FOREGROUND_SERVICE,BIND_VPN_SERVICE

# Android API 版本
android.api = 31
android.minapi = 21
android.ndk = 25b

# Android 架构
android.archs = arm64-v8a,armeabi-v7a

# 服务声明
services = VpnService:src/vpn_service.py

# 方向
orientation = portrait

# 全屏
fullscreen = 0

# 后台运行
android.wakelock = True

# 日志级别
log_level = 2

# 安装位置
android.install_location = auto

# 自动接受SDK许可证
android.accept_sdk_license = True

# 复制文件
android.add_src = libs,assets

# Gradle 依赖 (添加ONNX Runtime Android AAR)
android.gradle_dependencies = com.microsoft.onnxruntime:onnxruntime-android:1.15.0

# AndroidManifest.xml 额外配置
android.manifest.intent_filters = 

# 应用主题和硬件加速（修复黑屏）
android.manifest.application = {"android:hardwareAccelerated": "true", "android:largeHeap": "true"}
android.manifest.application_meta_data = 

# p4a额外参数
p4a.bootstrap = sdl2
# 使用master分支（更稳定）
p4a.branch = master
# 使用预构建dist跳过libffi编译
# p4a.skip_update = True  


[buildozer]

# 日志级别 (0 = 错误, 1 = 信息, 2 = 调试)
log_level = 2

# 警告级别
warn_on_root = 1

# 构建目录
build_dir = ./.buildozer

# 二进制目录
bin_dir = ./bin

