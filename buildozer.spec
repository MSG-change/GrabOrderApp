[app]

# Application name (English for Kivy compatibility)
title = Grab Order Assistant

# Package name
package.name = graborder

# Package domain
package.domain = com.graborder

# Main program entry
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json,js,ttf

# Version
version = 1.5.0

# Application requirements (Python packages)
# Minimal requirements for stability
requirements = python3,kivy==2.3.0,pillow,requests,pyjnius,android

# Android configuration
android.permissions = INTERNET,ACCESS_NETWORK_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE,SYSTEM_ALERT_WINDOW,FOREGROUND_SERVICE
android.api = 31
android.minapi = 21
android.ndk = 25b
android.archs = arm64-v8a,armeabi-v7a
android.accept_sdk_license = True

# Service declaration
services = VpnService:src/vpn_service.py

# Orientation
orientation = portrait

# Full screen
fullscreen = 0

# Background running
android.wakelock = True

# Gradle dependencies
android.gradle_dependencies = com.microsoft.onnxruntime:onnxruntime-android:1.15.0

# Application theme and hardware acceleration
android.manifest.application = {"android:hardwareAccelerated": "true", "android:largeHeap": "true"}

# p4a configuration - use stable defaults
p4a.bootstrap = sdl2

[buildozer]

# Log level (0 = error, 1 = info, 2 = debug)
log_level = 2

# Warning level
warn_on_root = 1
