[app]

# 应用名称
title = 抢单助手

# 包名
package.name = graborder

# 包域名
package.domain = com.graborder

# 主程序入口
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json,onnx,js

# 版本号
version = 1.0.0

# 应用需求（Python 包）
# numpy使用p4a recipe（预编译），不从PyPI安装
# Android使用远程API生成W参数，不需要execjs
requirements = python3,kivy==2.2.1,pillow,requests,numpy,pyjnius,android

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

# 应用主题
android.manifest.application_meta_data = 

# p4a额外参数
p4a.bootstrap = sdl2
p4a.branch = master

# 使用更新的python-for-android版本（修复了一些编译问题）
p4a.source_dir = 

# 使用本地自定义recipes
p4a.local_recipes = ./recipes

# 注意：不要全局禁用setup_py，否则numpy recipe无法编译
# p4a.setup_py = True (默认值，允许recipe使用setup.py)  


[buildozer]

# 日志级别 (0 = 错误, 1 = 信息, 2 = 调试)
log_level = 2

# 警告级别
warn_on_root = 1

# 构建目录
build_dir = ./.buildozer

# 二进制目录
bin_dir = ./bin

