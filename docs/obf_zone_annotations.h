/*===----------------------------------------------------------------------===*\
|*                                                                            *|
|*  obf_zone_annotations.h  --  Zone 授权调用路径 VM 保护注解                  *|
|*                                                                            *|
|*  用法：在最终用户的源码中包含此头文件，并用 OBF_ZONE_VM 宏包裹 zone 调用。   *|
|*  这样最终用户编译时，zone 授权的关键路径会被 VMPass 虚拟化保护。            *|
|*                                                                            *|
|*  示例：                                                                    *|
|*      #include "obf_zone_annotations.h"                                     *|
|*                                                                            *|
|*      OBF_ZONE_VM                                                           *|
|*      int check_license(void) {                                             *|
|*          return xollvm_zone_require("main");                               *|
|*      }                                                                     *|
|*                                                                            *|
|*  注意：zone_runtime 本身是预编译静态库，其内部代码无法被最终用户的         *|
|*  混淆工具链保护。此头文件的作用是把 zone 调用的入口点（用户代码中的函数）   *|
|*  用 VM 保护，增加攻击者定位验签/授权逻辑的难度。                            *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifndef OBF_ZONE_ANNOTATIONS_H
#define OBF_ZONE_ANNOTATIONS_H

#include "obf_annotations.h"

/*
 * OBF_ZONE_VM
 *   用 VM 保护 zone 授权调用路径。适用于最终用户代码中直接调用
 *   xollvm_zone_require / xollvm_zone_capability_begin 等函数的入口函数。
 *
 *   推荐配合 noinline 防止内联器把函数体复制到未保护区域。
 */
#define OBF_ZONE_VM          OBF_FN("vm(hardened=1)")
#define OBF_ZONE_VM_MAX      OBF_FN("vm(preset=max)")

/*
 * OBF_ZONE_GATE(capability)
 *   在函数入口插入 zoneauth 门控 + VM 保护。capability 为授权能力名。
 *   示例：OBF_ZONE_GATE("main")
 */
#define OBF_ZONE_GATE(cap) \
    OBF_FN("zoneauth(capability=" cap ", policy=fail_closed), vm(hardened=1)")

/*
 * OBF_ZONE_GATE_VM(capability, vm_spec)
 *   自定义 VM 配置的 zone 门控。
 *   示例：OBF_ZONE_GATE_VM("main", "vm(preset=max, handlerVariants=4)")
 */
#define OBF_ZONE_GATE_VM(cap, vm_spec) \
    OBF_FN("zoneauth(capability=" cap ", policy=fail_closed), " vm_spec)

#endif /* OBF_ZONE_ANNOTATIONS_H */
