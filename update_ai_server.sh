#!/bin/bash
# 更新 AI 服务器地址配置

# 颜色定义
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}🔧 更新 AI 服务器配置${NC}"
echo -e "${BLUE}================================${NC}"

# 获取服务器地址
if [ -z "$1" ]; then
    echo -e "${YELLOW}请输入 AI 服务器地址（例如: 154.219.127.13）:${NC}"
    read SERVER_IP
else
    SERVER_IP=$1
fi

if [ -z "$SERVER_IP" ]; then
    echo -e "${YELLOW}❌ 未提供服务器地址${NC}"
    exit 1
fi

AI_SERVER_URL="http://${SERVER_IP}:8889"

echo -e "${GREEN}✓ 服务器地址: ${AI_SERVER_URL}${NC}"
echo ""

# 1. 更新 main.py
echo -e "${BLUE}1. 更新 main.py...${NC}"
if [ -f "main.py" ]; then
    sed -i.bak "s|os.environ\['AI_SERVER_URL'\] = '.*'|os.environ['AI_SERVER_URL'] = '${AI_SERVER_URL}'|" main.py
    echo -e "${GREEN}   ✓ main.py 已更新${NC}"
else
    echo -e "${YELLOW}   ⚠ main.py 未找到${NC}"
fi

# 2. 更新 AI_SERVER_CONFIG.md
echo -e "${BLUE}2. 更新 AI_SERVER_CONFIG.md...${NC}"
if [ -f "AI_SERVER_CONFIG.md" ]; then
    sed -i.bak "s|IP: .*|IP: ${SERVER_IP}|" AI_SERVER_CONFIG.md
    sed -i.bak "s|完整地址: .*|完整地址: ${AI_SERVER_URL}|" AI_SERVER_CONFIG.md
    sed -i.bak "s|http://[0-9.]*:8889|${AI_SERVER_URL}|g" AI_SERVER_CONFIG.md
    echo -e "${GREEN}   ✓ AI_SERVER_CONFIG.md 已更新${NC}"
else
    echo -e "${YELLOW}   ⚠ AI_SERVER_CONFIG.md 未找到${NC}"
fi

# 3. 创建环境变量文件
echo -e "${BLUE}3. 创建 .env 文件...${NC}"
cat > .env << EOF
# AI 服务器配置
AI_SERVER_URL=${AI_SERVER_URL}
EOF
echo -e "${GREEN}   ✓ .env 文件已创建${NC}"

# 4. 创建启动脚本
echo -e "${BLUE}4. 创建启动脚本...${NC}"
cat > start_with_ai.sh << 'EOF'
#!/bin/bash
# 加载环境变量
if [ -f .env ]; then
    export $(cat .env | xargs)
fi

echo "🚀 启动抢单APP"
echo "🌐 AI服务器: $AI_SERVER_URL"
python main.py
EOF
chmod +x start_with_ai.sh
echo -e "${GREEN}   ✓ start_with_ai.sh 已创建${NC}"

# 5. 测试连接
echo ""
echo -e "${BLUE}5. 测试 AI 服务器连接...${NC}"
if command -v curl &> /dev/null; then
    echo -e "   正在连接 ${AI_SERVER_URL}/health ..."
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "${AI_SERVER_URL}/health")
    if [ "$RESPONSE" = "200" ]; then
        echo -e "${GREEN}   ✓ AI 服务器连接成功！${NC}"
        curl -s "${AI_SERVER_URL}/health" | python -m json.tool 2>/dev/null || echo ""
    else
        echo -e "${YELLOW}   ⚠ AI 服务器无法连接 (HTTP ${RESPONSE})${NC}"
        echo -e "${YELLOW}   请检查：${NC}"
        echo -e "${YELLOW}   1. 服务器 IP 是否正确${NC}"
        echo -e "${YELLOW}   2. 防火墙是否开放 8889 端口${NC}"
        echo -e "${YELLOW}   3. Docker 容器是否正在运行${NC}"
    fi
else
    echo -e "${YELLOW}   ⚠ curl 未安装，跳过连接测试${NC}"
fi

echo ""
echo -e "${BLUE}================================${NC}"
echo -e "${GREEN}✅ 配置更新完成！${NC}"
echo -e "${BLUE}================================${NC}"
echo ""
echo -e "${GREEN}使用方法：${NC}"
echo -e "  1. 直接运行: ${BLUE}./start_with_ai.sh${NC}"
echo -e "  2. 或设置环境变量: ${BLUE}export AI_SERVER_URL=${AI_SERVER_URL}${NC}"
echo -e "  3. 测试远程AI: ${BLUE}python test_geetest_remote.py${NC}"
echo ""
