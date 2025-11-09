# ✅ 准备就绪！可以打包了

## 依赖状态

- ✅ **OpenSSL 3** - 已安装
- ✅ **JDK 17** - 已安装
- ✅ **环境变量** - 已配置

## 🚀 立即打包

```bash
# 使用自动配置环境的脚本
./BUILD_APK.sh

# 或者手动打包
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"
export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig"
buildozer android debug
```

## ⏱️ 预计时间

- **首次打包**: 30-60 分钟
- **后续打包**: 5-10 分钟

## 📦 打包完成后

APK 文件位置：
```
bin/graborder-*.apk
```

安装到手机：
```bash
adb install -r bin/*.apk
```

## 📱 使用流程

1. **安装 APK**
2. **用 HttpCanary 抓包获取 Token**
3. **在 APK 中粘贴 Token**
4. **点击 Start**
5. **开始抢单！**

---

**现在就开始打包吧！** 🚀
