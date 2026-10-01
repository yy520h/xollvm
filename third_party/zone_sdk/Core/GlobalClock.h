#ifndef GLOBAL_CLOCK_H
#define GLOBAL_CLOCK_H

#include <chrono>
#include <stdexcept>
/// <summary>
/// 自定义时钟
/// </summary>
class GlobalClock
{
public:
    // 禁止实例化，确保全局唯一
    GlobalClock() = delete;
    GlobalClock(const GlobalClock&) = delete;
    GlobalClock& operator=(const GlobalClock&) = delete;

    /// <summary>
    /// 初始化时钟，设置初始时间戳并开始运行
    /// </summary>
    /// <param name="initialTimestamp">初始时间戳(毫秒)</param>
    static void Start(long long initialTimestamp);

    /// <summary>
    /// 获取当前时钟时间戳(毫秒)
    /// </summary>
    /// <returns>当前时间戳(毫秒)</returns>
    static long long GetCurrentTimestamp();

    /// <summary>
    /// 修正当前时间
    /// </summary>
    /// <param name="newTimestamp">新的时间戳(毫秒)</param>
    static void CorrectTime(long long newTimestamp);

    /// <summary>
    /// 获取当前系统的Unix时间戳(毫秒)
    /// </summary>
    /// <returns>当前系统时间戳(毫秒)</returns>
    static long long GetCurrentSystemTimestamp();

    /// <summary>
    /// 检查时钟是否正在运行
    /// </summary>
    /// <returns>如果时钟正在运行则返回true，否则返回false</returns>
    static bool IsRunning();

private:
    // 记录时钟启动时的系统时间戳(毫秒)
    static long long _systemStartTime;
    // 记录时钟启动时的基准时间戳(毫秒)
    static long long _baseTimestamp;
    // 时间偏移量，用于修正时间
    static long long _timeOffset;
    // 标识时钟是否已启动
    static bool _isRunning;
};

#endif // GLOBAL_CLOCK_H
