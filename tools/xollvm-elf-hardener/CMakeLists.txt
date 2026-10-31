# ============================================================================
# xollvm-elf-hardener — post-link ELF cave auditor (Task 7) and, later, the
# manifest sealer (Task 8). Uses LLVM's Object/BinaryFormat/Support APIs.
# ============================================================================
list(APPEND LLVM_TOOLCHAIN_TOOLS xollvm-elf-hardener)
add_llvm_tool(xollvm-elf-hardener
  xollvm-elf-hardener.cpp
  MaterialManifest.cpp
  VMTargets.cpp
)
target_include_directories(xollvm-elf-hardener PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../include")
if(ANDROID)
  set(_HARDENER_NDK_ROOT "$ENV{XOLLVM_NDK}")
  if(NOT _HARDENER_NDK_ROOT)
    set(_HARDENER_NDK_ROOT "$ENV{HOME}/android-ndk-r30-ollvm-r23-beta3")
  endif()
  set(_HARDENER_NDK_CXX "${_HARDENER_NDK_ROOT}/toolchains/llvm/prebuilt/linux-arm64/sysroot/usr/lib/aarch64-linux-android")
  target_link_options(xollvm-elf-hardener PRIVATE -nostdlib++)
  target_link_libraries(xollvm-elf-hardener PRIVATE
    "${_HARDENER_NDK_CXX}/libc++_static.a"
    "${_HARDENER_NDK_CXX}/libc++abi.a")
else()
  target_link_options(xollvm-elf-hardener PRIVATE -static-libstdc++)
endif()
llvm_config(xollvm-elf-hardener Object BinaryFormat Support)
