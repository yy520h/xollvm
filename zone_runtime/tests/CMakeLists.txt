cmake_minimum_required(VERSION 3.10)
project(cloud_value_manager_tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 测试用小掩码（0xFFF），使暴力搜索合法 V 在毫秒级完成
add_definitions(
    -DVM_DISPATCH_OFFSET_MASK=0xFFFu
    -DVM_DISPATCH_WINDOW_SEC=60
    -DVM_DISPATCH_PREFETCH_SEC=50
)

find_package(OpenSSL REQUIRED)

add_executable(test_cloud_value_manager
    test_cloud_value_manager.cpp
    ../cloud_value_manager.cpp
)

target_include_directories(test_cloud_value_manager PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(test_cloud_value_manager PRIVATE
    OpenSSL::Crypto
    pthread
)

target_compile_options(test_cloud_value_manager PRIVATE -Wall -Wextra -g)

enable_testing()
add_test(NAME cloud_value_manager_test COMMAND test_cloud_value_manager)
