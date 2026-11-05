# Makefile for local demos

CXX = g++
CXXFLAGS = -std=c++20 -I.. -Wall -O2
LDFLAGS = -lssl -lcrypto -lpthread

# 目标文件路径
BUILD_DIR = ../build-test
RUNTIME_OBJS = \
	$(BUILD_DIR)/aarch64_relocation.o \
	$(BUILD_DIR)/exception_handler.o \
	$(BUILD_DIR)/multi_shard_coordinator.o \
	$(BUILD_DIR)/elf_audit_rules.o \
	$(BUILD_DIR)/runtime_guardian_integration.o \
	$(BUILD_DIR)/chaff_scheduler_optimized.o \
	$(BUILD_DIR)/raw_socket_cloud_provider.o \
	$(BUILD_DIR)/cloud_provider_manager.o \
	$(BUILD_DIR)/performance_monitor.o

# 需要的其他运行时对象文件
EXTRA_OBJS = \
	../runtime/cloud_material/dynamic_vm_schema.o \
	../runtime/cloud_material/integrity_state.o

all: local_server_demo local_client_demo

# 编译额外需要的运行时模块
../runtime/cloud_material/dynamic_vm_schema.o: ../runtime/cloud_material/dynamic_vm_schema.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

../runtime/cloud_material/integrity_state.o: ../runtime/cloud_material/integrity_state.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 服务端demo（不依赖运行时模块）
local_server_demo: local_server_demo.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)
	@echo "✓ 服务端demo编译完成"

# 客户端demo（依赖运行时模块）
local_client_demo: local_client_demo.cpp $(RUNTIME_OBJS) $(EXTRA_OBJS)
	$(CXX) $(CXXFLAGS) $< $(RUNTIME_OBJS) $(EXTRA_OBJS) -o $@ $(LDFLAGS)
	@echo "✓ 客户端demo编译完成"

clean:
	rm -f local_server_demo local_client_demo $(EXTRA_OBJS)

run-server: local_server_demo
	@echo "启动本地服务端（端口8080）..."
	./local_server_demo

run-client: local_client_demo
	@echo "运行客户端测试..."
	./local_client_demo

test: all
	@echo "请在两个终端分别运行："
	@echo "  终端1: make run-server"
	@echo "  终端2: make run-client"

.PHONY: all clean run-server run-client test
