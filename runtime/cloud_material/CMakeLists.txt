if(TARGET xovm-dynamic-vm-runtime)
  return()
endif()

set(_XOVM_DYNAMIC_VM_RUNTIME_SOURCES
  dynamic_vm_schema.cpp
  dynamic_vm_artifact.cpp
  dynamic_vm_shard.cpp
  dynamic_vm_window_provider.cpp
  dynamic_vm_runtime.cpp
  continuation_executor.cpp
  integrity_state.cpp
  jit_handler_buffer.cpp
)

if(DEFINED LLVM_MAIN_SRC_DIR)
  add_llvm_library(xovm-dynamic-vm-runtime
    PARTIAL_SOURCES_INTENDED
    ${_XOVM_DYNAMIC_VM_RUNTIME_SOURCES})
else()
  add_library(xovm-dynamic-vm-runtime STATIC
    ${_XOVM_DYNAMIC_VM_RUNTIME_SOURCES})
endif()
add_library(xovm::dynamic-vm-runtime ALIAS xovm-dynamic-vm-runtime)

target_compile_features(xovm-dynamic-vm-runtime PUBLIC cxx_std_20)
target_include_directories(xovm-dynamic-vm-runtime PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../..>"
)
target_link_libraries(xovm-dynamic-vm-runtime PUBLIC OpenSSL::Crypto)
set_target_properties(xovm-dynamic-vm-runtime PROPERTIES
  POSITION_INDEPENDENT_CODE ON
)
