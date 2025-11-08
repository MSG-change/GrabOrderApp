# PC预览指南

在打包APK之前，可以先在PC上预览应用界面，确保UI正常显示。

## 快速预览

### 方法1：使用预览脚本（推荐）

```bash
cd GrabOrderApp
./preview_pc.sh
```

### 方法2：手动运行

```bash
cd GrabOrderApp

# 安装依赖
pip3 install kivy pillow requests

# 运行应用
python3 main.py
```

## 预览功能

PC预览版本会：
- ✅ 显示完整的UI界面
- ✅ 测试所有UI组件
- ✅ 显示日志输出
- ✅ 测试按钮点击等功能

**注意**：
- ⚠️ VPN抓包功能在PC上不可用（需要Android系统）
- ⚠️ 抢单服务需要真实Token才能测试
- ⚠️ Geetest识别需要模型文件

## 预览截图

预览时你会看到：
1. **标题**: 🚀 抢单助手
2. **状态显示**: 当前运行状态
3. **Token输入框**: 可以手动输入Token
4. **控制按钮**: 启动/停止按钮
5. **VPN开关**: VPN抓包开关（PC上不可用）
6. **日志区域**: 实时显示运行日志

## 常见问题

### 1. 导入错误

如果遇到 `ModuleNotFoundError`:
```bash
pip3 install kivy pillow requests
```

### 2. 字体显示问题

PC上如果中文显示为方块，可以：
- 忽略（APK中会包含中文字体）
- 或者安装中文字体到系统

### 3. 窗口大小

预览窗口可能比手机屏幕大，这是正常的。

## 下一步

预览确认UI正常后：
1. 提交代码到GitHub
2. 触发GitHub Actions构建
3. 下载生成的APK
4. 安装到手机测试

## 查看日志

PC预览时，日志会直接输出到终端，你可以看到：
- 应用启动过程
- UI构建过程
- 错误信息（如果有）

