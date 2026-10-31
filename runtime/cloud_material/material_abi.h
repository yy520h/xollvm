#ifndef XOVM_MATERIAL_ABI_H
#define XOVM_MATERIAL_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { XOVM_MATERIAL_ABI_VERSION = 1, XOVM_MATERIAL_RECORD_VERSION = 1,
       XOVM_MATERIAL_RECORD_SIZE = 120, XOVM_MATERIAL_HEADER_SIZE = 16,
       XOVM_MODE_SESSION = 1, XOVM_MODE_LEASE = 2, XOVM_MODE_OPERATION = 3,
       XOVM_INVALID_OPCODE = 65535 };

typedef struct XovmMaterialHandle XovmMaterialHandle;
typedef struct {
    uint32_t abi_version;
    uint32_t bytecode_size;
    const uint8_t *bytecode;
    const uint16_t *decode_map;
    uint32_t decode_salt;
    uint32_t reserved;
    uint64_t generation;
} XovmMaterialView;

typedef struct {
    uint32_t abi_version;
    uint32_t mode;
    uint8_t build_id[32];
    uint8_t region_id[32];
    uint8_t engine_abi_hash[32];
} XovmRegionDescriptor;

// ELF 编解码必须逐字段按 little-endian 写读，不能 memcpy 宿主结构。
typedef struct {
    uint8_t magic[8]; /* XOVMMAT\0 */
    uint16_t version;
    uint16_t header_size;
    uint32_t record_size;
    XovmRegionDescriptor descriptor;
} XovmMaterialRecord;

// 仅冻结 C ABI；句柄注册/认证/生命周期由后续 runtime 任务实现。
XovmMaterialHandle *__xovm_material_acquire(const XovmRegionDescriptor *region);
void __xovm_material_view(const XovmMaterialHandle *handle, XovmMaterialView *out);
void __xovm_material_release(XovmMaterialHandle *handle);

#ifdef __cplusplus
}
#define XOVM_ABI_ASSERT static_assert
#else
#define XOVM_ABI_ASSERT _Static_assert
#endif

XOVM_ABI_ASSERT(sizeof(XovmRegionDescriptor) == 104, "descriptor size");
XOVM_ABI_ASSERT(offsetof(XovmRegionDescriptor, abi_version) == 0, "abi offset");
XOVM_ABI_ASSERT(offsetof(XovmRegionDescriptor, mode) == 4, "mode offset");
XOVM_ABI_ASSERT(offsetof(XovmRegionDescriptor, build_id) == 8, "build offset");
XOVM_ABI_ASSERT(offsetof(XovmRegionDescriptor, region_id) == 40, "region offset");
XOVM_ABI_ASSERT(offsetof(XovmRegionDescriptor, engine_abi_hash) == 72, "engine offset");
XOVM_ABI_ASSERT(sizeof(XovmMaterialRecord) == 120, "record size");
XOVM_ABI_ASSERT(offsetof(XovmMaterialRecord, version) == 8, "version offset");
XOVM_ABI_ASSERT(offsetof(XovmMaterialRecord, header_size) == 10, "header size offset");
XOVM_ABI_ASSERT(offsetof(XovmMaterialRecord, record_size) == 12, "record size offset");
XOVM_ABI_ASSERT(offsetof(XovmMaterialRecord, descriptor) == 16, "wrapper descriptor offset");
XOVM_ABI_ASSERT(sizeof(void *) == 8, "foundation requires 64-bit target");
XOVM_ABI_ASSERT(sizeof(XovmMaterialView) == 40, "view size");
XOVM_ABI_ASSERT(offsetof(XovmMaterialView, abi_version) == 0, "view ABI offset");
XOVM_ABI_ASSERT(offsetof(XovmMaterialView, bytecode_size) == 4, "view size offset");
XOVM_ABI_ASSERT(offsetof(XovmMaterialView, bytecode) == 8, "view bytecode offset");
XOVM_ABI_ASSERT(offsetof(XovmMaterialView, decode_map) == 16, "view map offset");
XOVM_ABI_ASSERT(offsetof(XovmMaterialView, decode_salt) == 24, "view salt offset");
XOVM_ABI_ASSERT(offsetof(XovmMaterialView, reserved) == 28, "view reserved offset");
XOVM_ABI_ASSERT(offsetof(XovmMaterialView, generation) == 32, "view generation offset");
#undef XOVM_ABI_ASSERT
#endif
