# CloudMaterial Runtime Library
# 动态 VM 保护架构运行时组件

cmake_minimum_required(VERSION 3.13.4)

# 查找依赖库
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

# CloudMaterial 运行时库
add_library(CloudMaterialRuntime STATIC
    window_cache.cpp
    security_monitor.cpp
    zone_adapter.cpp
    vm_integration.cpp
)

target_include_directories(CloudMaterialRuntime PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIRS}
)

target_link_libraries(CloudMaterialRuntime
    ${OPENSSL_LIBRARIES}
    ${CURL_LIBRARIES}
    pthread
)

# 编译选项
target_compile_features(CloudMaterialRuntime PUBLIC cxx_std_17)
target_compile_options(CloudMaterialRuntime PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
)

# 安装
install(TARGETS CloudMaterialRuntime
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES
    window_cache.h
    security_monitor.h
    zone_adapter.h
    vm_integration.h
    DESTINATION include/xollvm/cloud_material
)
