#pragma once
// 在工程预处理器中定义 ZoneDebug（如 Debug 配置 /DZoneDebug）后输出 WebSocket 调试日志。

#if defined(ZoneDebug)
#include <iostream>
#define ZONE_WS_LOG(...) \
	do { std::cerr << "[ZoneCore/WS] " << __VA_ARGS__ << std::endl; } while (0)
#else
#define ZONE_WS_LOG(...) ((void)0)
#endif
