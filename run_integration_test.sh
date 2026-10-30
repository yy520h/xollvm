#!/data/data/com.termux/files/usr/bin/bash

echo "═══════════════════════════════════════════════════════════════"
echo "  本地集成测试 - 客户端与服务端通信"
echo "═══════════════════════════════════════════════════════════════"

# 1. 启动服务器
echo ""
echo "[1/3] 启动服务器..."
./demos/local_server_demo &
SERVER_PID=$!
sleep 3

# 检查服务器是否运行
if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    echo "      ✗ 服务器启动失败"
    exit 1
fi
echo "      ✓ 服务器运行中 (PID: $SERVER_PID)"

# 2. 测试基本连接
echo ""
echo "[2/3] 测试基本TCP连接..."
./demos/test_connection
if [ $? -eq 0 ]; then
    echo "      ✓ TCP连接成功"
else
    echo "      ✗ TCP连接失败"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# 重启服务器（因为accept后退出了）
kill $SERVER_PID 2>/dev/null
sleep 1
./demos/local_server_demo &
SERVER_PID=$!
sleep 2

# 3. 运行完整客户端测试
echo ""
echo "[3/3] 运行完整客户端测试..."
echo ""
./demos/local_client_demo
CLIENT_EXIT=$?

# 清理
kill $SERVER_PID 2>/dev/null
sleep 1
kill -9 $SERVER_PID 2>/dev/null

echo ""
echo "═══════════════════════════════════════════════════════════════"
if [ $CLIENT_EXIT -eq 0 ]; then
    echo "  ✅ 本地集成测试完成"
else
    echo "  ⚠️  客户端测试失败 (退出码: $CLIENT_EXIT)"
fi
echo "═══════════════════════════════════════════════════════════════"

exit $CLIENT_EXIT
