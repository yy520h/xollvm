function(add_sensitive_attack_baseline_tests source_dir)
  foreach(tool IN ITEMS clang llvm-readelf llvm-objdump)
    if(NOT TARGET ${tool})
      message(STATUS
        "SensitiveAttackBaselineTests disabled: required target ${tool} is unavailable")
      return()
    endif()
  endforeach()

  add_custom_target(SensitiveAttackBaselineTests
    COMMAND "${CMAKE_COMMAND}" -E env
            "XOLLVM_TEST_CLANG=$<TARGET_FILE:clang>"
            "${Python3_EXECUTABLE}" -m pytest
            utils/attack_gates/test_sensitive_attack_baseline.py -q
    DEPENDS clang llvm-readelf llvm-objdump
    WORKING_DIRECTORY "${source_dir}"
    USES_TERMINAL
  )
endfunction()
