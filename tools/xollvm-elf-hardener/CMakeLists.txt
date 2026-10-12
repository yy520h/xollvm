# ============================================================================
# xollvm-elf-hardener — post-link ELF cave auditor (Task 7) and, later, the
# manifest sealer (Task 8). Uses LLVM's Object/BinaryFormat/Support APIs.
# ============================================================================
list(APPEND LLVM_TOOLCHAIN_TOOLS xollvm-elf-hardener)
add_llvm_tool(xollvm-elf-hardener
  xollvm-elf-hardener.cpp
)
llvm_config(xollvm-elf-hardener Object BinaryFormat Support)
