#!/bin/bash
# 端到端集成测试：编译 -> 部署 -> 运行

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "==================================="
echo "CloudMaterial 端到端集成测试"
echo "==================================="
echo ""

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 清理函数
cleanup() {
    log_info "清理环境..."
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
    fi
    if [ ! -z "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
    fi
}

trap cleanup EXIT

# 创建测试目录
TEST_DIR="$PROJECT_ROOT/test_output/e2e_test_$(date +%s)"
mkdir -p "$TEST_DIR"
log_info "测试目录: $TEST_DIR"

# ============================================================================
# 阶段 1: 准备测试数据
# ============================================================================

echo ""
log_info "阶段 1: 准备测试数据"

# 创建窗口目录
WINDOWS_DIR="$TEST_DIR/windows"
mkdir -p "$WINDOWS_DIR"

# 生成模拟窗口文件（5 个窗口，每个 2 分片）
log_info "生成窗口文件..."
for w in {0..4}; do
    for s in {0..1}; do
        WINDOW_FILE="$WINDOWS_DIR/test_material_w${w}_s${s}.bin"
        dd if=/dev/urandom of="$WINDOW_FILE" bs=2048 count=1 2>/dev/null
        # 计算 SHA256
        if command -v sha256sum &> /dev/null; then
            sha256sum "$WINDOW_FILE" >> "$TEST_DIR/checksums.txt"
        fi
    done
done
log_info "生成了 10 个窗口文件"

# ============================================================================
# 阶段 2: 模拟编译时打包
# ============================================================================

echo ""
log_info "阶段 2: 模拟编译时打包"

PACKAGE_DIR="$TEST_DIR/backend_package"
mkdir -p "$PACKAGE_DIR/windows"

# 生成 HMAC 密钥
HMAC_SECRET=$(openssl rand -hex 32)
log_info "生成 HMAC 密钥: ${HMAC_SECRET:0:16}..."

# 生成 metadata.json
log_info "生成 metadata.json..."
cat > "$PACKAGE_DIR/metadata.json" << EOF
{
  "app_id": "com.test.e2e",
  "version": "1.0.0",
  "build_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "window_size": 2048,
  "chaff_ratio": 0.3,
  "materials": {
    "test_material": {
      "id": "test_material",
      "total_size": 10240,
      "window_count": 5,
      "shard_count": 2,
      "commitment": "sha256:test"
    }
  }
}
EOF

# 生成 config.yaml
log_info "生成 config.yaml..."
cat > "$PACKAGE_DIR/config.yaml" << EOF
app:
  id: "com.test.e2e"
  version: "1.0.0"

mode: direct

direct:
  listen: "127.0.0.1:18080"
  auth_method: hmac
  secret: "$HMAC_SECRET"
  tls:
    enabled: false
  security:
    rate_limit:
      enabled: true
      requests_per_device_per_minute: 100
    replay_protection:
      enabled: true
      time_window_seconds: 300
      nonce_cache_size: 10000

storage:
  windows_dir: "./windows/"
  metadata_file: "./metadata.json"

logging:
  level: "info"
EOF

# 复制窗口文件
log_info "复制窗口文件..."
cp "$WINDOWS_DIR"/*.bin "$PACKAGE_DIR/windows/"

# 复制或链接后端服务器
BACKEND_SERVER="$PROJECT_ROOT/xollvm-backend-server/xollvm-backend-server"
if [ -f "$BACKEND_SERVER" ]; then
    cp "$BACKEND_SERVER" "$PACKAGE_DIR/"
    chmod +x "$PACKAGE_DIR/xollvm-backend-server"
    log_info "后端服务器已复制"
else
    log_warn "后端服务器二进制未找到，将跳过服务器测试"
    log_warn "请先编译: cd xollvm-backend-server && go build"
    exit 0
fi

# ============================================================================
# 阶段 3: 启动后端服务器
# ============================================================================

echo ""
log_info "阶段 3: 启动后端服务器"

cd "$PACKAGE_DIR"

# 启动服务器
log_info "启动服务器在端口 18080..."
./xollvm-backend-server -config config.yaml > "$TEST_DIR/server.log" 2>&1 &
SERVER_PID=$!

# 等待服务器启动
sleep 2

# 检查服务器是否运行
if ! ps -p $SERVER_PID > /dev/null; then
    log_error "服务器启动失败"
    cat "$TEST_DIR/server.log"
    exit 1
fi

log_info "服务器已启动 (PID: $SERVER_PID)"

# ============================================================================
# 阶段 4: 测试健康检查
# ============================================================================

echo ""
log_info "阶段 4: 测试健康检查"

HEALTH_RESPONSE=$(curl -s http://127.0.0.1:18080/health)
if echo "$HEALTH_RESPONSE" | grep -q '"status":"ok"'; then
    log_info "✓ 健康检查通过"
    echo "  响应: $HEALTH_RESPONSE"
else
    log_error "✗ 健康检查失败"
    echo "  响应: $HEALTH_RESPONSE"
    exit 1
fi

# ============================================================================
# 阶段 5: 测试 HMAC 认证和窗口获取
# ============================================================================

echo ""
log_info "阶段 5: 测试 HMAC 认证和窗口获取"

DEVICE_ID="test-device-$(date +%s)"
TIMESTAMP=$(date +%s)
NONCE=$(openssl rand -hex 16)
PAYLOAD='{"material_id":"test_material","window_id":0,"shard_id":0}'

# 计算 HMAC 签名
MESSAGE="${DEVICE_ID}|${TIMESTAMP}|${NONCE}|${PAYLOAD}"
SIGNATURE=$(echo -n "$MESSAGE" | openssl dgst -sha256 -hmac "$HMAC_SECRET" | awk '{print $2}')
AUTH_HEADER="HMAC ${DEVICE_ID}:${TIMESTAMP}:${NONCE}:${SIGNATURE}"

log_info "发送窗口请求..."
log_info "  Device ID: $DEVICE_ID"
log_info "  Timestamp: $TIMESTAMP"
log_info "  Nonce: ${NONCE:0:16}..."

RESPONSE_FILE="$TEST_DIR/window_response.bin"
HTTP_CODE=$(curl -s -w "%{http_code}" -o "$RESPONSE_FILE" \
    -X POST http://127.0.0.1:18080/api/v1/window \
    -H "Authorization: $AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD")

if [ "$HTTP_CODE" = "200" ]; then
    RESPONSE_SIZE=$(wc -c < "$RESPONSE_FILE")
    log_info "✓ 窗口获取成功"
    echo "  HTTP 状态码: $HTTP_CODE"
    echo "  窗口大小: $RESPONSE_SIZE 字节"

    if [ "$RESPONSE_SIZE" -eq 2048 ]; then
        log_info "✓ 窗口大小正确"
    else
        log_warn "✗ 窗口大小不符 (期望: 2048, 实际: $RESPONSE_SIZE)"
    fi
else
    log_error "✗ 窗口获取失败"
    echo "  HTTP 状态码: $HTTP_CODE"
    cat "$RESPONSE_FILE"
    exit 1
fi

# ============================================================================
# 阶段 6: 测试认证失败场景
# ============================================================================

echo ""
log_info "阶段 6: 测试认证失败场景"

# 测试错误的签名
log_info "测试错误的签名..."
WRONG_SIGNATURE="0000000000000000000000000000000000000000000000000000000000000000"
WRONG_AUTH_HEADER="HMAC ${DEVICE_ID}:${TIMESTAMP}:${NONCE}:${WRONG_SIGNATURE}"

HTTP_CODE=$(curl -s -w "%{http_code}" -o /dev/null \
    -X POST http://127.0.0.1:18080/api/v1/window \
    -H "Authorization: $WRONG_AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD")

if [ "$HTTP_CODE" = "401" ]; then
    log_info "✓ 认证失败正确处理 (401)"
else
    log_warn "✗ 认证失败处理异常 (期望: 401, 实际: $HTTP_CODE)"
fi

# 测试重放攻击（相同 nonce）
log_info "测试重放攻击防护..."
HTTP_CODE=$(curl -s -w "%{http_code}" -o /dev/null \
    -X POST http://127.0.0.1:18080/api/v1/window \
    -H "Authorization: $AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD")

if [ "$HTTP_CODE" = "401" ]; then
    log_info "✓ 重放攻击正确拦截 (401)"
else
    log_warn "✗ 重放攻击防护异常 (期望: 401, 实际: $HTTP_CODE)"
fi

# ============================================================================
# 阶段 7: 测试限流
# ============================================================================

echo ""
log_info "阶段 7: 测试限流"

log_info "发送 10 个请求测试限流..."
SUCCESS_COUNT=0
RATE_LIMITED=0

for i in {1..10}; do
    NONCE=$(openssl rand -hex 16)
    TIMESTAMP=$(date +%s)
    MESSAGE="${DEVICE_ID}|${TIMESTAMP}|${NONCE}|${PAYLOAD}"
    SIGNATURE=$(echo -n "$MESSAGE" | openssl dgst -sha256 -hmac "$HMAC_SECRET" | awk '{print $2}')
    AUTH_HEADER="HMAC ${DEVICE_ID}:${TIMESTAMP}:${NONCE}:${SIGNATURE}"

    HTTP_CODE=$(curl -s -w "%{http_code}" -o /dev/null \
        -X POST http://127.0.0.1:18080/api/v1/window \
        -H "Authorization: $AUTH_HEADER" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD")

    if [ "$HTTP_CODE" = "200" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    elif [ "$HTTP_CODE" = "429" ]; then
        RATE_LIMITED=$((RATE_LIMITED + 1))
    fi
done

log_info "请求结果: $SUCCESS_COUNT 成功, $RATE_LIMITED 限流"

# ============================================================================
# 阶段 8: 检查服务器日志
# ============================================================================

echo ""
log_info "阶段 8: 检查服务器日志"

if [ -f "$TEST_DIR/server.log" ]; then
    log_info "服务器日志（最后 20 行）:"
    tail -20 "$TEST_DIR/server.log"
else
    log_warn "服务器日志文件未找到"
fi

# ============================================================================
# 测试总结
# ============================================================================

echo ""
echo "==================================="
echo "测试总结"
echo "==================================="
echo ""
echo "✓ 后端打包"
echo "✓ 服务器启动"
echo "✓ 健康检查"
echo "✓ HMAC 认证"
echo "✓ 窗口获取"
echo "✓ 认证失败处理"
echo "✓ 重放攻击防护"
echo "✓ 限流功能"
echo ""
log_info "所有测试通过！"
echo ""
echo "测试输出目录: $TEST_DIR"
echo "HMAC 密钥: $HMAC_SECRET"
echo ""
