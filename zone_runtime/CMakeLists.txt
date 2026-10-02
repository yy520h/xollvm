set(XOLLVM_ZONE_SDK_ROOT
  "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/zone_sdk"
  CACHE PATH "Bundled Zone SDK root")
set(XOLLVM_ZONE_SDK_INCLUDE "${XOLLVM_ZONE_SDK_ROOT}" CACHE PATH
  "Zone SDK root containing ZoneHelper.h and Core/")
if(NOT XOLLVM_ZONE_SDK_INCLUDE)
  set(XOLLVM_ZONE_SDK_INCLUDE "${XOLLVM_ZONE_SDK_ROOT}" CACHE PATH
    "Zone SDK root containing ZoneHelper.h and Core/" FORCE)
endif()
set(XOLLVM_ZONE_SDK_ARCHIVE "" CACHE FILEPATH
  "Optional prebuilt official Zone SDK archive")
set(XOLLVM_ZONE_CURL_ARCHIVE
  "${XOLLVM_ZONE_SDK_ROOT}/curl_core/libcurl_core.a" CACHE FILEPATH
  "Bundled Zone SDK curl static archive")
set(XOLLVM_ZONE_ZLIB_ARCHIVE
  "${XOLLVM_ZONE_SDK_ROOT}/zlib_core/libzlib_core.a" CACHE FILEPATH
  "Bundled Zone SDK zlib static archive")
set(XOLLVM_ZONE_OPENSSL_DIR
  "${XOLLVM_ZONE_SDK_ROOT}/openssl_core" CACHE PATH
  "Bundled Zone SDK OpenSSL directory")
if(NOT XOLLVM_ZONE_CURL_ARCHIVE)
  set(XOLLVM_ZONE_CURL_ARCHIVE
    "${XOLLVM_ZONE_SDK_ROOT}/curl_core/libcurl_core.a" CACHE FILEPATH
    "Bundled Zone SDK curl static archive" FORCE)
endif()
if(NOT XOLLVM_ZONE_ZLIB_ARCHIVE)
  set(XOLLVM_ZONE_ZLIB_ARCHIVE
    "${XOLLVM_ZONE_SDK_ROOT}/zlib_core/libzlib_core.a" CACHE FILEPATH
    "Bundled Zone SDK zlib static archive" FORCE)
endif()
if(NOT XOLLVM_ZONE_OPENSSL_DIR)
  set(XOLLVM_ZONE_OPENSSL_DIR
    "${XOLLVM_ZONE_SDK_ROOT}/openssl_core" CACHE PATH
    "Bundled Zone SDK OpenSSL directory" FORCE)
endif()

set(XOLLVM_ZONE_LINK_MODE "bundled" CACHE STRING
  "Zone link mode: bundled or external")
set_property(CACHE XOLLVM_ZONE_LINK_MODE PROPERTY STRINGS bundled external)
if(NOT XOLLVM_ZONE_LINK_MODE STREQUAL "bundled" AND
   NOT XOLLVM_ZONE_LINK_MODE STREQUAL "external")
   message(FATAL_ERROR "XOLLVM_ZONE_LINK_MODE must be bundled or external")
endif()
set(XOLLVM_ZONE_EXTERNAL_CURL "" CACHE FILEPATH
  "External Zone curl archive")
set(XOLLVM_ZONE_EXTERNAL_ZLIB "" CACHE FILEPATH
  "External Zone zlib archive")
set(XOLLVM_ZONE_EXTERNAL_SSL "" CACHE FILEPATH
  "External Zone libssl archive")
set(XOLLVM_ZONE_EXTERNAL_CRYPTO "" CACHE FILEPATH
  "External Zone libcrypto archive")
if(XOLLVM_ZONE_SDK_INCLUDE)
  set(_ZONE_SDK_ROOT "${XOLLVM_ZONE_SDK_INCLUDE}")
  set(_ZONE_SDK_CORE "${_ZONE_SDK_ROOT}/Core")
  set(_ZONE_SDK_SOURCES
    "${_ZONE_SDK_ROOT}/Core/ZoneHelper.cpp"
    "${_ZONE_SDK_ROOT}/Core/ZoneHelperCore.cpp"
    "${_ZONE_SDK_ROOT}/Core/ZoneLib.cpp"
    "${_ZONE_SDK_ROOT}/Core/EncryptCore.cpp"
    "${_ZONE_SDK_ROOT}/Core/RC4.cpp"
    "${_ZONE_SDK_ROOT}/Core/base64.cpp"
    "${_ZONE_SDK_ROOT}/Core/md5.cpp"
    "${_ZONE_SDK_ROOT}/Core/hw_info.cpp"
    "${_ZONE_SDK_ROOT}/Core/GlobalClock.cpp"
    "${_ZONE_SDK_ROOT}/Core/SocketClientCore.cpp"
    "${_ZONE_SDK_ROOT}/Core/cyanray/WebSocketClient.cpp"
    "${_ZONE_SDK_ROOT}/Core/WNetWrap/wnetwrap.cpp")

  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  if(XOLLVM_ZONE_LINK_MODE STREQUAL "external")
    foreach(_ZONE_EXTERNAL_ARCHIVE
        XOLLVM_ZONE_EXTERNAL_CURL XOLLVM_ZONE_EXTERNAL_ZLIB
        XOLLVM_ZONE_EXTERNAL_SSL XOLLVM_ZONE_EXTERNAL_CRYPTO)
      if(NOT ${_ZONE_EXTERNAL_ARCHIVE} OR
         NOT EXISTS "${${_ZONE_EXTERNAL_ARCHIVE}}")
        message(FATAL_ERROR
          "external Zone dependency ${_ZONE_EXTERNAL_ARCHIVE} is missing")
      endif()
    endforeach()
  endif()
  if(XOLLVM_ZONE_LINK_MODE STREQUAL "bundled")
  set(_ZONE_PREFIX_TOOL "${CMAKE_CURRENT_SOURCE_DIR}/zone_prefix_archive.py")
  set(_ZONE_PRIVATE_DIR "${CMAKE_CURRENT_BINARY_DIR}/private")
  set(_ZONE_PREFIX_ARGS
    --prefix xollvm_zone_curl_=curl_
    --prefix xollvm_zone_zlib_=zlib_
    --prefix xollvm_zone_zlib_=deflate
    --prefix xollvm_zone_zlib_=inflate
    --prefix xollvm_zone_zlib_=crc32
    --prefix xollvm_zone_zlib_=adler32
    --prefix xollvm_zone_zlib_=compress
    --prefix xollvm_zone_zlib_=uncompress
    --prefix xollvm_zone_zlib_=gz
    --prefix xollvm_zone_ssl_=SSL_
    --prefix xollvm_zone_ssl_=TLS_
    --prefix xollvm_zone_ssl_=BIO_
    --prefix xollvm_zone_ssl_=ERR_
    --prefix xollvm_zone_ssl_=X509
    --prefix xollvm_zone_ssl_=ASN1_
    --prefix xollvm_zone_crypto_=EVP_
    --prefix xollvm_zone_crypto_=CRYPTO_
    --prefix xollvm_zone_crypto_=OPENSSL_
    --prefix xollvm_zone_crypto_=AES_
    --prefix xollvm_zone_crypto_=DES_
    --prefix xollvm_zone_crypto_=DSA_
    --prefix xollvm_zone_crypto_=EC_
    --prefix xollvm_zone_crypto_=BN_
    --prefix xollvm_zone_crypto_=HMAC_
    --prefix xollvm_zone_crypto_=MD
    --prefix xollvm_zone_crypto_=SHA
    --prefix xollvm_zone_crypto_=RSA_
    --prefix xollvm_zone_crypto_=PKCS
    --prefix xollvm_zone_crypto_=RAND_)
  set(_ZONE_PRIVATE_CURL "${_ZONE_PRIVATE_DIR}/libxollvm_zone_curl.a")
  set(_ZONE_PRIVATE_ZLIB "${_ZONE_PRIVATE_DIR}/libxollvm_zone_zlib.a")
  set(_ZONE_PRIVATE_SSL "${_ZONE_PRIVATE_DIR}/libxollvm_zone_ssl.a")
  set(_ZONE_PRIVATE_CRYPTO "${_ZONE_PRIVATE_DIR}/libxollvm_zone_crypto.a")
  add_custom_command(OUTPUT "${_ZONE_PRIVATE_CURL}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_ZONE_PRIVATE_DIR}"
    COMMAND ${Python3_EXECUTABLE} "${_ZONE_PREFIX_TOOL}" ${_ZONE_PREFIX_ARGS}
      "${XOLLVM_ZONE_CURL_ARCHIVE}" --output "${_ZONE_PRIVATE_CURL}"
    DEPENDS "${XOLLVM_ZONE_CURL_ARCHIVE}" "${_ZONE_PREFIX_TOOL}")
  add_custom_command(OUTPUT "${_ZONE_PRIVATE_ZLIB}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_ZONE_PRIVATE_DIR}"
    COMMAND ${Python3_EXECUTABLE} "${_ZONE_PREFIX_TOOL}" ${_ZONE_PREFIX_ARGS}
      "${XOLLVM_ZONE_ZLIB_ARCHIVE}" --output "${_ZONE_PRIVATE_ZLIB}"
    DEPENDS "${XOLLVM_ZONE_ZLIB_ARCHIVE}" "${_ZONE_PREFIX_TOOL}")
  add_custom_command(OUTPUT "${_ZONE_PRIVATE_SSL}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_ZONE_PRIVATE_DIR}"
    COMMAND ${Python3_EXECUTABLE} "${_ZONE_PREFIX_TOOL}" ${_ZONE_PREFIX_ARGS}
      "${XOLLVM_ZONE_OPENSSL_DIR}/libssl.a" --output "${_ZONE_PRIVATE_SSL}"
    DEPENDS "${XOLLVM_ZONE_OPENSSL_DIR}/libssl.a" "${_ZONE_PREFIX_TOOL}")
  add_custom_command(OUTPUT "${_ZONE_PRIVATE_CRYPTO}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_ZONE_PRIVATE_DIR}"
    COMMAND ${Python3_EXECUTABLE} "${_ZONE_PREFIX_TOOL}" ${_ZONE_PREFIX_ARGS}
      "${XOLLVM_ZONE_OPENSSL_DIR}/libcrypto.a" --output "${_ZONE_PRIVATE_CRYPTO}"
    DEPENDS "${XOLLVM_ZONE_OPENSSL_DIR}/libcrypto.a" "${_ZONE_PREFIX_TOOL}")
  add_custom_target(xollvm_zone_curl_private DEPENDS "${_ZONE_PRIVATE_CURL}")
  add_custom_target(xollvm_zone_zlib_private DEPENDS "${_ZONE_PRIVATE_ZLIB}")
  add_custom_target(xollvm_zone_ssl_private DEPENDS "${_ZONE_PRIVATE_SSL}")
  add_custom_target(xollvm_zone_crypto_private DEPENDS "${_ZONE_PRIVATE_CRYPTO}")

  add_library(xollvm_zone_sdk STATIC
    zone_wrapper.cpp capability_protocol.cpp capability_client.cpp
    vm_dispatch_value.cpp cloud_value_manager.cpp ${_ZONE_SDK_SOURCES})
  target_include_directories(xollvm_zone_sdk PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}" "${_ZONE_SDK_ROOT}" "${_ZONE_SDK_CORE}"
    "${_ZONE_SDK_ROOT}/curl_core/curl/include"
    "${_ZONE_SDK_ROOT}/curl_core"
    "${_ZONE_SDK_ROOT}/zlib_core"
    "${_ZONE_SDK_ROOT}/openssl_core")
  target_compile_features(xollvm_zone_sdk PRIVATE cxx_std_17)
  target_compile_options(xollvm_zone_sdk PRIVATE -ffunction-sections -fdata-sections)

  if(XOLLVM_ZONE_SDK_ARCHIVE)
    target_link_libraries(xollvm_zone_sdk PUBLIC "${XOLLVM_ZONE_SDK_ARCHIVE}")
  endif()
  set(_ZONE_PRIVATE_SDK "${_ZONE_PRIVATE_DIR}/libxollvm_zone_sdk_private.a")
  add_custom_command(OUTPUT "${_ZONE_PRIVATE_SDK}"
    COMMAND ${Python3_EXECUTABLE} "${_ZONE_PREFIX_TOOL}" ${_ZONE_PREFIX_ARGS}
      --runtime-source "$<TARGET_FILE:xollvm_zone_sdk>"
      "$<TARGET_FILE:xollvm_zone_sdk>"
      "${_ZONE_PRIVATE_CURL}" "${_ZONE_PRIVATE_ZLIB}"
      "${_ZONE_PRIVATE_SSL}" "${_ZONE_PRIVATE_CRYPTO}"
      --output "${_ZONE_PRIVATE_SDK}"
    DEPENDS xollvm_zone_sdk
      xollvm_zone_curl_private xollvm_zone_zlib_private
      xollvm_zone_ssl_private xollvm_zone_crypto_private
      "${_ZONE_PREFIX_TOOL}")
  add_custom_target(xollvm_zone_sdk_private DEPENDS "${_ZONE_PRIVATE_SDK}")
  add_custom_command(OUTPUT "${_ZONE_PRIVATE_SDK}.audited"
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/zone_archive_audit.py"
      --prefix xollvm_zone_ "${_ZONE_PRIVATE_SDK}"
    COMMAND ${CMAKE_COMMAND} -E touch "${_ZONE_PRIVATE_SDK}.audited"
    DEPENDS "${_ZONE_PRIVATE_SDK}"
    VERBATIM)
  add_custom_target(xollvm_zone_sdk_audit DEPENDS "${_ZONE_PRIVATE_SDK}.audited")
  endif()

  add_executable(xollvm_zone_wrapper_link_smoke
    zone_wrapper_link_smoke.cpp)
  target_include_directories(xollvm_zone_wrapper_link_smoke PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}")
  if(XOLLVM_ZONE_LINK_MODE STREQUAL "bundled")
    target_link_libraries(xollvm_zone_wrapper_link_smoke PRIVATE
      "${_ZONE_PRIVATE_SDK}")
    add_dependencies(xollvm_zone_wrapper_link_smoke
      xollvm_zone_sdk_private xollvm_zone_sdk_audit)
  else()
    target_link_libraries(xollvm_zone_wrapper_link_smoke PRIVATE
      xollvm_zone_sdk
      "${XOLLVM_ZONE_EXTERNAL_CURL}" "${XOLLVM_ZONE_EXTERNAL_ZLIB}"
      "${XOLLVM_ZONE_EXTERNAL_SSL}" "${XOLLVM_ZONE_EXTERNAL_CRYPTO}")
  endif()
  target_link_options(xollvm_zone_wrapper_link_smoke PRIVATE
    -Wl,--gc-sections)

  add_executable(xollvm_zone_live_check zone_live_check.cpp)
  target_include_directories(xollvm_zone_live_check PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}")
  if(XOLLVM_ZONE_LINK_MODE STREQUAL "bundled")
    target_link_libraries(xollvm_zone_live_check PRIVATE "${_ZONE_PRIVATE_SDK}")
    add_dependencies(xollvm_zone_live_check
      xollvm_zone_sdk_private xollvm_zone_sdk_audit)
  else()
    target_link_libraries(xollvm_zone_live_check PRIVATE
      xollvm_zone_sdk
      "${XOLLVM_ZONE_EXTERNAL_CURL}" "${XOLLVM_ZONE_EXTERNAL_ZLIB}"
      "${XOLLVM_ZONE_EXTERNAL_SSL}" "${XOLLVM_ZONE_EXTERNAL_CRYPTO}")
  endif()
  target_link_options(xollvm_zone_live_check PRIVATE
    -Wl,--gc-sections)

  configure_file(xollvm_zone_link.py
    "${CMAKE_CURRENT_BINARY_DIR}/xollvm_zone_link.py" COPYONLY)
  configure_file(xollvm-zone-clang
    "${CMAKE_CURRENT_BINARY_DIR}/xollvm-zone-clang" COPYONLY)
endif()
