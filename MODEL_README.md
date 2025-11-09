# 九宫格验证模型文件说明

## 重要提示

由于 `best_siamese_model.pth` 文件大小为 137MB，超过了 GitHub 的 100MB 文件限制，该文件未包含在仓库中。

## 获取模型文件

### 方法一：从本地复制
如果你有本地的模型文件，可以直接复制：
```bash
cp /path/to/best_siamese_model.pth /path/to/GrabOrderApp/
```

### 方法二：从原项目获取
模型文件位于 siam-autolabel 项目根目录：
```bash
cp ../best_siamese_model.pth ./
```

## 模型文件说明

- **文件名**: `best_siamese_model.pth`
- **大小**: 137.44 MB
- **用途**: Siamese 神经网络模型，用于识别九宫格验证码
- **准确率**: 98.88%
- **放置位置**: GrabOrderApp 根目录

## 验证模型是否可用

在应用启动时，会自动检测模型文件是否存在。如果模型文件缺失，日志会显示：
```
[WARNING] 九宫格验证器加载失败: [Errno 2] No such file or directory: 'best_siamese_model.pth'
```

## Android 部署注意事项

1. **APK 大小**: 包含模型文件后，APK 大小会增加约 137MB
2. **加载时间**: 首次加载模型可能需要几秒钟
3. **内存占用**: 模型加载后会占用一定内存

## 替代方案

如果不想在 APK 中包含大模型文件，可以考虑：

1. **网络下载**: 应用首次启动时从服务器下载模型
2. **远程 API**: 使用远程服务器进行九宫格识别
3. **轻量级模型**: 训练一个更小的模型（可能牺牲准确率）

## 相关文件

- `libs/siamese_network.py`: Siamese 网络定义
- `libs/geetest_helper_local.py`: 使用模型的验证器
- `jiyanv4/gcaptcha4_click.js`: W参数加密
