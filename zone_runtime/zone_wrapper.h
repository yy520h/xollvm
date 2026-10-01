#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 这些接口由最终目标程序与官方 Zone SDK wrapper 一起链接。 */
int xollvm_zone_initialize(const char* software_id, const char* version,
                           const char* encrypt_key, const char* encrypt_iv,
                           const char* algorithm,
                           const char* capability_key_id,
                           uint32_t heartbeat_period_sec,
                           uint32_t offline_grace_sec);
int xollvm_zone_login_card(const char* card);
int xollvm_zone_first_heartbeat(void);
int xollvm_zone_refresh_lease(void);
int xollvm_zone_require(const char* capability);
int xollvm_zone_capability_begin(const char* operation, const char* payload);
int xollvm_zone_capability_require(const char* operation,
                                   const char* request_hash);
int xollvm_zone_capability_seed(const char* operation, const char* code_manifest,
                                char* out_hex, uint32_t out_size);
void xollvm_zone_capability_clear(void);
char* xollvm_zone_vm_dispatch_value(void);
int xollvm_zone_vm_dispatch_refresh(void);
void xollvm_zone_shutdown(void);
void xollvm_zone_set_shutdown_mode(int automatic);

#ifdef __cplusplus
}
#endif
