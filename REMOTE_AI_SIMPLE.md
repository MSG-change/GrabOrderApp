# 远程AI识别 - 简化版

基于v1.5.0稳定版本，最小化改动添加远程AI支持。

## 快速使用

### 1. 启动AI服务（Mac端）

```bash
python3 ai_server_simple.py 8889
```

### 2. 配置客户端（手机端）

```bash
# 设置环境变量
export AI_SERVER_URL=http://192.168.31.232:8889
```

### 3. 运行APP

APP会自动：
1. 检测到AI_SERVER_URL环境变量
2. 使用远程AI服务识别九宫格
3. 如果远程失败，自动降级到本地处理

## 工作流程

```
1. 检测到订单
2. 触发抢单
3. 发送captcha_id到AI服务器
4. AI服务器自动获取图片并识别
5. 返回识别结果[0-8]
6. 本地生成W参数
7. 构建geeDto
8. 发送抢单请求
```

## 特点

- ✅ 基于v1.5.0稳定版本
- ✅ 最小化改动
- ✅ 向后兼容
- ✅ 自动降级
- ✅ 无需修改buildozer.spec
- ✅ APK大小不变

## 配置

| 参数 | 说明 | 默认值 |
|------|------|--------|
| AI_SERVER_URL | AI服务器地址 | 无（使用本地） |
| captcha_id | 验证码ID | 045e2c229998a88721e32a763bc0f7b8 |

## 测试

```bash
# 测试AI服务
curl http://192.168.31.232:8889/health

# 测试识别
curl -X POST http://192.168.31.232:8889/api/v1/recognize \
  -H "Content-Type: application/json" \
  -d '{"captcha_id": "045e2c229998a88721e32a763bc0f7b8"}'
```
