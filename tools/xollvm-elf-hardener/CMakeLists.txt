# ============================================================================
# xollvm-elf-hardener — post-link ELF cave auditor (Task 7) and, later, the
# manifest sealer (Task 8). Uses LLVM's Object/BinaryFormat/Support APIs.
# ============================================================================
add_llvm_executable(xollvm-elf-hardener
  xollvm-elf-hardener.cpp
)
llvm_config(xollvm-elf-hardener Object BinaryFormat Support)
