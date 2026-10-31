cmake_minimum_required(VERSION 3.20)
project(xovm_cloud_material_backend LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Version floors require confirmation against the deployment host package set.
find_package(SQLite3 3.35 REQUIRED)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
set(XOLLVM_PROJECT_ROOT "$ENV{XOLLVM_PROJECT_ROOT}" CACHE PATH
    "Project root containing demo/jni/zone_runtime/Core/nlohmann/json.hpp")
find_package(nlohmann_json 3.10 QUIET)
if(NOT TARGET nlohmann_json::nlohmann_json)
    find_path(XOLLVM_NLOHMANN_INCLUDE_DIR nlohmann/json.hpp
        HINTS "${XOLLVM_PROJECT_ROOT}/demo/jni/zone_runtime/Core")
    if(NOT XOLLVM_NLOHMANN_INCLUDE_DIR)
        message(FATAL_ERROR
            "nlohmann_json 3.10+ not found; set XOLLVM_PROJECT_ROOT to the configured project root")
    endif()
    file(STRINGS "${XOLLVM_NLOHMANN_INCLUDE_DIR}/nlohmann/json.hpp" _json_major
        REGEX "^#define NLOHMANN_JSON_VERSION_MAJOR [0-9]+")
    file(STRINGS "${XOLLVM_NLOHMANN_INCLUDE_DIR}/nlohmann/json.hpp" _json_minor
        REGEX "^#define NLOHMANN_JSON_VERSION_MINOR [0-9]+")
    file(STRINGS "${XOLLVM_NLOHMANN_INCLUDE_DIR}/nlohmann/json.hpp" _json_patch
        REGEX "^#define NLOHMANN_JSON_VERSION_PATCH [0-9]+")
    if(NOT _json_major MATCHES "^#define NLOHMANN_JSON_VERSION_MAJOR 3([ \t]|$)" OR
       NOT _json_minor MATCHES "^#define NLOHMANN_JSON_VERSION_MINOR (1[0-9]|[2-9][0-9]+)([ \t]|$)")
        message(FATAL_ERROR "The project-root nlohmann JSON header must be version 3.10 or newer")
    endif()
    add_library(xollvm_nlohmann_json INTERFACE)
    target_include_directories(xollvm_nlohmann_json INTERFACE
        "${XOLLVM_NLOHMANN_INCLUDE_DIR}")
    add_library(nlohmann_json::nlohmann_json ALIAS xollvm_nlohmann_json)
endif()

add_library(xovm-cloud-material-backend
    canonical_json.cpp
    http_contract.cpp
    admin_repository.cpp
    build_snapshot.cpp
    auth_policy.cpp
    session_state.cpp
    state_wal.cpp
    checkpoint.cpp
    config.cpp
    process_lock.cpp
    http_server.cpp
    startup.cpp
    runtime_providers.cpp
    runtime_admin.cpp
    protocol_service.cpp
    response_crypto.cpp
    ../cloud_material/material_package.cpp
    ../cloud_material/material_protocol.cpp)
target_include_directories(xovm-cloud-material-backend PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../cloud_material)
target_link_libraries(xovm-cloud-material-backend PUBLIC
    SQLite3::SQLite3
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json)

add_executable(xovm-cloud-material-backend-server
    main.cpp)
target_link_libraries(xovm-cloud-material-backend-server PRIVATE
    xovm-cloud-material-backend)

add_executable(xovm-cloud-material-backend-fixture-server
    main.cpp
    ../../utils/CloudMaterialProviderFixture.cpp)
target_link_libraries(xovm-cloud-material-backend-fixture-server PRIVATE
    xovm-cloud-material-backend)

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)

    add_test(NAME xovm-cloud-material-backend-process-startup
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/../../utils/test_cloud_material_backend_startup.py
            $<TARGET_FILE:xovm-cloud-material-backend-server>)

    add_test(NAME xovm-cloud-material-backend-provider-fixture
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/../../utils/test_cloud_material_backend_provider_fixture.py
            $<TARGET_FILE:xovm-cloud-material-backend-fixture-server>)

    add_test(NAME xovm-cloud-material-backend-tls-proxy
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/../../utils/test_cloud_material_backend_tls_proxy.py)

    add_executable(xovm-cloud-material-backend-tests
        ../../utils/CloudMaterialBackendProtocolTest.cpp)
    target_link_libraries(xovm-cloud-material-backend-tests PRIVATE
        xovm-cloud-material-backend)
    add_test(NAME xovm-cloud-material-backend-tests
        COMMAND xovm-cloud-material-backend-tests)

    add_executable(xovm-cloud-material-snapshot-tests
        ../../utils/CloudMaterialSnapshotTest.cpp)
    target_link_libraries(xovm-cloud-material-snapshot-tests PRIVATE
        xovm-cloud-material-backend)
    add_test(NAME xovm-cloud-material-snapshot-tests
        COMMAND xovm-cloud-material-snapshot-tests)

    add_executable(xovm-cloud-material-service-tests
        ../../utils/CloudMaterialBackendServiceTest.cpp)
    target_link_libraries(xovm-cloud-material-service-tests PRIVATE
        xovm-cloud-material-backend)
    add_test(NAME xovm-cloud-material-service-tests
        COMMAND xovm-cloud-material-service-tests)

    add_executable(xovm-cloud-material-wal-tests
        ../../utils/CloudMaterialWalTest.cpp)
    target_link_libraries(xovm-cloud-material-wal-tests PRIVATE
        xovm-cloud-material-backend)
    add_test(NAME xovm-cloud-material-wal-tests
        COMMAND xovm-cloud-material-wal-tests)

    add_executable(xovm-cloud-material-config-tests
        ../../utils/CloudMaterialBackendConfigTest.cpp)
    target_link_libraries(xovm-cloud-material-config-tests PRIVATE
        xovm-cloud-material-backend)
    add_test(NAME xovm-cloud-material-config-tests
        COMMAND xovm-cloud-material-config-tests)

    add_executable(xovm-cloud-material-http-tests
        ../../utils/CloudMaterialBackendHttpTest.cpp)
    target_link_libraries(xovm-cloud-material-http-tests PRIVATE
        xovm-cloud-material-backend)
    add_test(NAME xovm-cloud-material-http-tests
        COMMAND xovm-cloud-material-http-tests)

    add_executable(xovm-cloud-material-startup-tests
        ../../utils/CloudMaterialBackendStartupTest.cpp)
    target_link_libraries(xovm-cloud-material-startup-tests PRIVATE
        xovm-cloud-material-backend)
    add_test(NAME xovm-cloud-material-startup-tests
        COMMAND xovm-cloud-material-startup-tests)

    add_executable(xovm-cloud-material-task7-tests
        ../../utils/CloudMaterialTask7Test.cpp)
    target_link_libraries(xovm-cloud-material-task7-tests PRIVATE
        xovm-cloud-material-backend)
    add_test(NAME xovm-cloud-material-task7-tests
        COMMAND xovm-cloud-material-task7-tests)

    add_executable(xovm-cloud-material-runtime-admin-tests
        ../../utils/CloudMaterialRuntimeAdminTest.cpp)
    target_link_libraries(xovm-cloud-material-runtime-admin-tests PRIVATE
        xovm-cloud-material-backend)
    add_test(NAME xovm-cloud-material-runtime-admin-tests
        COMMAND xovm-cloud-material-runtime-admin-tests)
endif()
