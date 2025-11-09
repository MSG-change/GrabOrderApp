[app]

# Application name (English for Kivy compatibility)
title = Grab Order Assistant

# Package name
package.name = graborder

# Package domain
package.domain = com.graborder

# Main program entry
source.dir = .
source.entry_point = main.py
source.include_exts = py,png,jpg,kv,atlas,json,onnx,js,ttf,xz
source.include_patterns = assets/*,libs/*,src/*

# Version
version = 1.2.0

# Application requirements (Python packages)
# Removed numpy dependency (using pure Python + PIL + Java ONNX Runtime)
# Android uses remote API for W parameter generation, no execjs needed
# Note: Frida removed from requirements to avoid architecture conflicts
# The app will use external Frida server approach for MuMu emulator
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

# Icon and splash screen
#icon.filename = %(source.dir)s/assets/icon.png
#presplash.filename = %(source.dir)s/assets/presplash.png

# Android permissions
android.permissions = INTERNET,ACCESS_NETWORK_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE,SYSTEM_ALERT_WINDOW,FOREGROUND_SERVICE,BIND_VPN_SERVICE

# Android API version
android.api = 31
android.minapi = 21
android.ndk = 25b

# Android architecture (support ARM64 and ARMv7)
android.archs = arm64-v8a,armeabi-v7a

# Service declaration
services = VpnService:src/vpn_service.py

# Orientation
orientation = portrait

# Full screen
fullscreen = 0

# Background running
android.wakelock = True

# Log level
log_level = 2

# Installation location
android.install_location = auto

# Automatically accept SDK license
android.accept_sdk_license = True

# Copy files
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

