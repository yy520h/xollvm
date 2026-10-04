# ============================================================================
# integrity SHA-256 stub build (mirrors aes_stub)
# ============================================================================
set(_INT_SRC  "${CMAKE_CURRENT_SOURCE_DIR}/integrity_sha256.c")
set(_INT_BIN2C "${CMAKE_CURRENT_SOURCE_DIR}/../aes_stub/aes_bin2c.py")

set(_INT_BC   "${CMAKE_CURRENT_BINARY_DIR}/integrity_sha256.bc")
set(_INT_INC  "${CMAKE_CURRENT_BINARY_DIR}/integrity_sha256_bc.inc")

add_custom_command(
  OUTPUT "${_INT_BC}"
  COMMAND "${_AES_CLANG_EXE}" -O2 -emit-llvm -c -ffreestanding
          -fno-builtin -fvisibility=hidden -target "${AES_STUB_TARGET}"
          -fno-pic -g0 "${_INT_SRC}" -o "${_INT_BC}"
  DEPENDS "${_INT_SRC}" ${_AES_CLANG_DEP}
  COMMENT "integrity: compiling SHA-256 stub -> LLVM bitcode"
  VERBATIM
)

add_custom_command(
  OUTPUT "${_INT_INC}"
  COMMAND "${Python3_EXECUTABLE}" "${_INT_BIN2C}" "${_INT_BC}" "${_INT_INC}"
  DEPENDS "${_INT_BC}" "${_INT_BIN2C}"
  COMMENT "integrity: embedding bitcode as C array"
  VERBATIM
)

add_custom_target(integrity_stub_inc DEPENDS "${_INT_INC}")

set(INTEGRITY_GENERATED_INC "${_INT_INC}" PARENT_SCOPE)
