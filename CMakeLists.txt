# ============================================================================
# xollvm — Obfuscator pass, built two ways from one source, with NO edits to
# any LLVM file:
#
#   * Loadable plugin (standalone, configured against an installed/exported
#     LLVM): builds Obfuscator.so, loaded via clang -fpass-plugin= /
#     opt -load-pass-plugin=. Linux/macOS only.
#
#   * Static in-tree extension (configured as part of an LLVM build via
#     -DLLVM_EXTERNAL_PROJECTS=Obfuscator
#     -DLLVM_EXTERNAL_OBFUSCATOR_SOURCE_DIR=<this dir>
#     -DLLVM_OBFUSCATOR_LINK_INTO_TOOLS=ON): compiled straight into clang/opt.
#     Works on Windows too. Registration flows through
#     getObfuscatorPluginInfo() via LLVM's generated HANDLE_EXTENSION.
#
# Both modes use add_llvm_pass_plugin(); LLVM decides module-vs-object from
# LLVM_OBFUSCATOR_LINK_INTO_TOOLS. There is no in-tree component library and no
# PassRegistry.def / PassBuilder.cpp glue anymore.
# ============================================================================

cmake_minimum_required(VERSION 3.20)


# ---------------------------------------------------------------------------
# Build-mode detection
#   In-LLVM-tree  : LLVM_MAIN_SRC_DIR is set (we were add_subdirectory'd by the
#                   LLVM build, e.g. via LLVM_EXTERNAL_PROJECTS). LLVM's CMake
#                   modules are already loaded.
#   Standalone    : configure on our own against an installed/exported LLVM.
# ---------------------------------------------------------------------------
if(NOT DEFINED LLVM_MAIN_SRC_DIR)
  project(xollvm C CXX)
  find_package(LLVM REQUIRED CONFIG)
  list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
  include(AddLLVM)
  include(HandleLLVMOptions)
  include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
  add_definitions(${LLVM_DEFINITIONS})
endif()

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)


# ---------------------------------------------------------------------------
# AES stub prerequisites (both modes)
# ---------------------------------------------------------------------------
if(NOT DEFINED AES_STUB_TARGET)
  set(AES_STUB_TARGET "${LLVM_HOST_TRIPLE}"
      CACHE STRING "Target triple used when compiling the AES stub")
endif()

# Pick the clang used to compile the AES stub to bitcode.
#   * Component/loadable builds may use the in-tree clang target directly.
#   * A static extension (LINK_INTO_TOOLS) must NOT depend on the in-tree clang:
#     clang links LLVMExtensions -> Obfuscator -> (aes) -> clang would be a
#     dependency cycle. Use an external clang in that case.
if(TARGET clang AND NOT LLVM_OBFUSCATOR_LINK_INTO_TOOLS)
  set(_AES_CLANG_EXE "$<TARGET_FILE:clang>")
  set(_AES_CLANG_DEP clang)
else()
  find_program(_AES_CLANG_EXE NAMES clang clang-22 clang-21 clang-20 clang-19)
  if(NOT _AES_CLANG_EXE)
    message(FATAL_ERROR "aes stub: external clang not found (needed to break the "
                        "LINK_INTO_TOOLS dependency cycle).")
  endif()
  set(_AES_CLANG_DEP "")
endif()

find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_subdirectory(aes_stub)
add_subdirectory(integrity_stub)

# ---------------------------------------------------------------------------
# CloudMaterial Runtime (动态 VM 保护运行时)
# ---------------------------------------------------------------------------
add_subdirectory(runtime/cloud_material)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
set(OBF_SOURCES
  Utils.cpp
  OpaqueUtils.cpp
  ObfDebug.cpp
  ObfMetrics.cpp
  ObfReport.cpp
  ObfuscationPipeline.cpp
  Substitution.cpp
  BogusControlFlow.cpp
  SplitBasicBlock.cpp
  Flattening.cpp
  MBAUtils.cpp
  MBAObfuscation.cpp
  ConstantEncryption.cpp
  SemanticDiffusion.cpp
  FunctionMerging.cpp
  StringEncryption.cpp
  VirtualCall.cpp
  AntiDecompiler.cpp
  ADec/ArchBackend.cpp
  ADec/Arch_X86_64.cpp
  ADec/Arch_AArch64.cpp
  ADec/GadgetPool.cpp
  ADec/Technique.cpp
  ADec/Tech_AsmGadgets.cpp
  ADec/Tech_IndirectBr.cpp
  ADec/Tech_DeadDecoy.cpp
  ADec/Tech_StackPollution.cpp
  ADec/Tech_CallTrampoline.cpp
  ADec/Tech_AliasConfusion.cpp
  ADec/Tech_FakeLoop.cpp
  ADec/Tech_RdtscStretch.cpp
  ADec/Tech_ConstLaunder.cpp
  AntiOptimizationShield.cpp
  VMPass.cpp
  VMPass_Requirements.cpp
  VMPass_Emitter.cpp
  VMPass_Material.cpp
  VMPass_Plan.cpp
  VMPass_Verifier.cpp
  VMPass_Impl.cpp
  VMPass_AntiDebug.cpp
  VMPass_Crypto.cpp
  VMPass_Decode.cpp
  VMPass_Layout.cpp
  VMPass_SuperOps.cpp
  VMPass_Targets.cpp
  VMWhiteBoxAES.cpp
  VMPass_WhiteBox.cpp
  VMPass_Dispatch.cpp
  VMPass_Handlers.cpp
  VMPass_Harden.cpp
  VMPass_Nested.cpp
  VMPass_Wrapper.cpp
  VMPass_Decoys.cpp
  VMPass_CloudMaterial.cpp
  VMPass_CloudConfig.cpp
  VMPass_CloudExport.cpp
  VMRuntime_CloudMaterial.cpp
  VMRuntime_SHA256.cpp
  AntiDebug.cpp
  ECC_KeyManager.cpp
  EHUtils.cpp
  TargetCompat.cpp
  FunctionObfContextAnalysis.cpp
  ObfuscationAnnotationAnalysis.cpp
  ObfuscationOptions.cpp
  ObfuscationConfig.cpp
  SensitiveDecision.cpp
  ElfIntegrity.cpp


  # Registration entry point (getObfuscatorPluginInfo / llvmGetPassPluginInfo).
  registration/PluginEntry.cpp
)


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------
# ObfuscationConfig.cpp uses C++ exceptions (try/throw/catch, contained within
# that TU). LLVM builds -fno-exceptions by default (MSVC tolerates, clang/gcc
# reject); opt this module into EH. AddLLVM applies the right per-compiler flag.
set(LLVM_REQUIRES_EH ON)

# Directory-scope includes: the module's own headers (include/llvm/Transforms/
# Obfuscator/** — prefix preserved) and the generated AES bitcode header. Set
# before the target so they apply whether add_llvm_pass_plugin builds a module
# (.so) or an object library (static extension).
include_directories(
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_BINARY_DIR}/aes_stub"
  "${CMAKE_CURRENT_BINARY_DIR}/integrity_stub"
)

# intrinsics_gen only exists inside an LLVM build tree.
if(TARGET intrinsics_gen)
  set(_OBF_DEPENDS DEPENDS intrinsics_gen)
else()
  set(_OBF_DEPENDS "")
endif()

# LINK_COMPONENTS policy differs by mode:
#
#   * Loadable .so: NONE on purpose. The plugin resolves LLVM symbols from the
#     host at load; static-linking LLVM here would give a second copy of LLVM
#     global state (e.g. the CommandLine registry) and abort at load
#     ("Option '...' registered more than once").
#
#   * Static extension (LINK_INTO_TOOLS): declare the LLVM components this
#     module actually references so CMake records the dependency edges and
#     orders the archives correctly. Without this, GNU ld's single pass can see
#     libLLVMLinker.a *before* libObfuscator.a on a tool's link line (e.g.
#     llvm-lto2), drop it as unreferenced, then fail with an undefined
#     reference to llvm::Linker::linkModules (used by StringEncryption /
#     VMPass). There is only ONE LLVM copy here (the tool's), so no double
#     global state -- these edges just fix ordering, they don't add a 2nd LLVM.
if(LLVM_OBFUSCATOR_LINK_INTO_TOOLS)
  # When statically linking into tools, declare all LLVM components used by obfuscator
  set(_OBF_LINK_COMPONENTS LINK_COMPONENTS
    Core
    Support
    Linker
    TransformUtils
    Analysis
    IRReader
    Passes
    Scalar
    InstCombine
    AggressiveInstCombine
    IPO
    Vectorize
    ObjCARCOpts
    Coroutines
    BitWriter
    BitReader
    TargetParser
    MC
  )
else()
  # For shared library builds, link against necessary LLVM components
  if(BUILD_SHARED_LIBS)
    set(_OBF_LINK_COMPONENTS LINK_COMPONENTS
      Core
      Support
      Linker
      TransformUtils
      Analysis
      IRReader
      Passes
      Scalar
      InstCombine
      AggressiveInstCombine
      IPO
      Vectorize
      ObjCARCOpts
      Coroutines
      BitWriter
      BitReader
    )
  else()
    set(_OBF_LINK_COMPONENTS "")
  endif()
endif()

add_llvm_pass_plugin(Obfuscator
  ${OBF_SOURCES}
  ${AES_GENERATED_INC}
  ${_OBF_DEPENDS}
  ${_OBF_LINK_COMPONENTS}
)
target_compile_features(Obfuscator PRIVATE cxx_std_20)
target_link_libraries(Obfuscator PRIVATE
  OpenSSL::Crypto
  xovm::dynamic-vm-runtime
)
if(TARGET obj.Obfuscator)
  target_compile_features(obj.Obfuscator PRIVATE cxx_std_20)
  target_link_libraries(obj.Obfuscator PRIVATE
    OpenSSL::Crypto
    xovm::dynamic-vm-runtime
  )
endif()

# For shared library builds, link only available shared LLVM libraries
# Note: Some LLVM components (Passes, ScalarOpts, etc.) may only be built as static
if(BUILD_SHARED_LIBS AND NOT LLVM_OBFUSCATOR_LINK_INTO_TOOLS)
  target_link_libraries(Obfuscator PRIVATE
    LLVMCore
    LLVMSupport
    LLVMTransformUtils
    LLVMAnalysis
    LLVMIRReader
  )
endif()

# Link OpenSSL for ECC_KeyManager
target_link_libraries(Obfuscator PRIVATE crypto ssl)

# The AES stub .inc must be generated before any obfuscator source that
# includes it is compiled. Under LINK_INTO_TOOLS add_llvm_pass_plugin compiles
# into obj.Obfuscator (not Obfuscator), so depend on both targets.
add_dependencies(Obfuscator aes_stub_inc integrity_stub_inc)
if(TARGET obj.Obfuscator)
  add_dependencies(obj.Obfuscator aes_stub_inc integrity_stub_inc)
endif()

if(DEFINED LLVM_MAIN_SRC_DIR)
  add_executable(xollvm-cloud-material-fs-helper
    tools/cloud-material/material-fs-helper.cpp)
  target_compile_features(xollvm-cloud-material-fs-helper PRIVATE cxx_std_20)
  if(ANDROID)
    set(_MATERIAL_NDK_ROOT "$ENV{XOLLVM_NDK}")
    if(NOT _MATERIAL_NDK_ROOT)
      set(_MATERIAL_NDK_ROOT "$ENV{HOME}/android-ndk-r30-ollvm-r23-beta3")
    endif()
    set(_MATERIAL_NDK_CXX "${_MATERIAL_NDK_ROOT}/toolchains/llvm/prebuilt/linux-arm64/sysroot/usr/lib/aarch64-linux-android")
    target_link_options(xollvm-cloud-material-fs-helper PRIVATE -nostdlib++)
    target_link_libraries(xollvm-cloud-material-fs-helper PRIVATE
      "${_MATERIAL_NDK_CXX}/libc++_static.a"
      "${_MATERIAL_NDK_CXX}/libc++abi.a")
  else()
    target_link_options(xollvm-cloud-material-fs-helper PRIVATE -static-libstdc++)
  endif()
  set_target_properties(xollvm-cloud-material-fs-helper PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${LLVM_BINARY_DIR}/bin")
  install(TARGETS xollvm-cloud-material-fs-helper RUNTIME DESTINATION bin)
  install(PROGRAMS tools/cloud-material/export.mjs
    DESTINATION bin RENAME xollvm-cloud-material-export)
endif()

# ---------------------------------------------------------------------------
# Cloud material runtime static library (xollvm-cloud-material-runtime)
#
# The obfuscator pass plugin only *declares* the __zone_* symbols in the IR
# it generates; their definitions live here. User binaries (executables and
# .so files) link this static library to resolve those symbols at link time.
# The .material/ directory is located as a sibling of the loaded module
# (matching clang's compile-time auto-export: <output>.material), overridable
# via XOLLVM_CLOUD_EXPORT_DIR for testing.
# ---------------------------------------------------------------------------
add_library(xollvm-cloud-material-runtime STATIC
  VMRuntime_CloudMaterial.cpp
  VMRuntime_SHA256.cpp)
target_compile_features(xollvm-cloud-material-runtime PRIVATE cxx_std_17)
# Position-independent so it can be linked into shared libraries (Android .so).
set_target_properties(xollvm-cloud-material-runtime PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  ARCHIVE_OUTPUT_DIRECTORY "${LLVM_BINARY_DIR}/lib")
# dladdr lives in libdl on Linux/Android.
target_link_libraries(xollvm-cloud-material-runtime PRIVATE ${CMAKE_DL_LIBS})
install(TARGETS xollvm-cloud-material-runtime
  ARCHIVE DESTINATION lib)
install(FILES include/llvm/Transforms/Obfuscator/VMRuntime_CloudMaterial.h
  DESTINATION include/llvm/Transforms/Obfuscator)

# 生成当前 LLVM 的类型表，避免回落到系统安装版本的 GenVT.inc。
if(TARGET vt_gen)
  add_dependencies(Obfuscator vt_gen)
  if(TARGET obj.Obfuscator)
    add_dependencies(obj.Obfuscator vt_gen)
  endif()
endif()

# Post-link ELF hardener (Task 7+). Only meaningful inside an LLVM build tree
# where AddLLVM's add_llvm_executable is available.
if(DEFINED LLVM_MAIN_SRC_DIR)
  add_subdirectory(tools/xollvm-elf-hardener)
  install(PROGRAMS tools/xollvm-link DESTINATION bin COMPONENT xollvm-link)
  add_custom_target(xollvm-link)
  add_llvm_install_targets(install-xollvm-link COMPONENT xollvm-link DEPENDS xollvm-link)
endif()

option(XOLLVM_ENABLE_MATERIAL_PACKAGE_TEST_BRIDGE
  "Enable the Android AArch64 Task 1 parser bridge in VMRequirementsTests" OFF)

if(LLVM_INCLUDE_TESTS AND DEFINED LLVM_MAIN_SRC_DIR)
  add_custom_target(ObfuscatorUnitTests)
  set(LLVM_LINK_COMPONENTS Core Support AsmParser)
  add_unittest(ObfuscatorUnitTests VMRequirementsTests
    utils/VMRequirementsTest.cpp
    utils/VMMaterialTest.cpp
    VMPass_Requirements.cpp
    VMPass_Emitter.cpp
    VMPass_Material.cpp
    VMPass_Verifier.cpp
    VMPass_Decode.cpp
    VMPass_Layout.cpp
    VMPass_SuperOps.cpp
    VMPass_Targets.cpp
    VMWhiteBoxAES.cpp
    VMPass_WhiteBox.cpp
  )
  target_link_libraries(VMRequirementsTests PRIVATE
    OpenSSL::Crypto
    xovm::dynamic-vm-runtime
  )
  add_dependencies(VMRequirementsTests xollvm-cloud-material-fs-helper)
  target_compile_definitions(VMRequirementsTests PRIVATE OBF_TEST_VM_IMPL=1)
  if(XOLLVM_ENABLE_MATERIAL_PACKAGE_TEST_BRIDGE)
    if(NOT ANDROID OR NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
      message(FATAL_ERROR
        "XOLLVM_ENABLE_MATERIAL_PACKAGE_TEST_BRIDGE requires Android AArch64")
    endif()
    set(_MATERIAL_PROJECT_ROOT "$ENV{XOLLVM_PROJECT_ROOT}")
    if(NOT IS_ABSOLUTE "${_MATERIAL_PROJECT_ROOT}")
      message(FATAL_ERROR
        "XOLLVM_ENABLE_MATERIAL_PACKAGE_TEST_BRIDGE requires absolute XOLLVM_PROJECT_ROOT")
    endif()
    set(_MATERIAL_ZONE "${_MATERIAL_PROJECT_ROOT}/demo/jni/zone_runtime")
    set(_MATERIAL_SSL "${_MATERIAL_PROJECT_ROOT}/demo/obj/openssl/arm64-v8a")
    if(NOT EXISTS "${_MATERIAL_ZONE}/Core/nlohmann/json.hpp" OR
       NOT EXISTS "${_MATERIAL_SSL}/libcrypto.a")
      message(FATAL_ERROR "material package test bridge dependencies missing")
    endif()
    target_sources(VMRequirementsTests PRIVATE
      runtime/cloud_material/material_package.cpp)
    target_compile_definitions(VMRequirementsTests PRIVATE
      XOLLVM_MATERIAL_PACKAGE_TEST_BRIDGE=1)
    target_compile_features(VMRequirementsTests PRIVATE cxx_std_20)
    target_include_directories(VMRequirementsTests PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}")
    target_include_directories(VMRequirementsTests SYSTEM PRIVATE
      "${_MATERIAL_ZONE}/Core"
      "${_MATERIAL_SSL}/include"
      "${_MATERIAL_ZONE}/openssl_core/src/include")
    target_link_libraries(VMRequirementsTests PRIVATE
      "${_MATERIAL_SSL}/libcrypto.a" "${CMAKE_DL_LIBS}")
  endif()
  if(ANDROID)
    set(_OBF_NDK_ROOT "$ENV{XOLLVM_NDK}")
    if(NOT _OBF_NDK_ROOT)
      set(_OBF_NDK_ROOT "$ENV{HOME}/android-ndk-r30-ollvm-r23-beta3")
    endif()
    set(_OBF_NDK_CXX "${_OBF_NDK_ROOT}/toolchains/llvm/prebuilt/linux-arm64/sysroot/usr/lib/aarch64-linux-android")
    if(NOT EXISTS "${_OBF_NDK_CXX}/libc++_static.a" OR
       NOT EXISTS "${_OBF_NDK_CXX}/libc++abi.a")
      message(FATAL_ERROR "VMRequirementsTests requires the NDK static libc++; set XOLLVM_NDK")
    endif()
    target_link_options(VMRequirementsTests PRIVATE -nostdlib++)
    target_link_libraries(VMRequirementsTests PRIVATE
      "${_OBF_NDK_CXX}/libc++_static.a"
      "${_OBF_NDK_CXX}/libc++abi.a")
  else()
    target_link_options(VMRequirementsTests PRIVATE -static-libstdc++)
  endif()
  if(LLVM_OBFUSCATOR_LINK_INTO_TOOLS)
    target_link_libraries(VMRequirementsTests PRIVATE Obfuscator)
    llvm_config(VMRequirementsTests Linker BitReader TransformUtils Analysis ScalarOpts IPO)
  endif()

  include(cmake/SensitiveAttackBaselineTests.cmake)
  add_sensitive_attack_baseline_tests("${CMAKE_CURRENT_SOURCE_DIR}")
endif()
