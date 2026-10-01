#include "GlobalClock.h"

// 静态成员变量初始化
long long GlobalClock::_systemStartTime = 0;
long long GlobalClock::_baseTimestamp = 0;
long long GlobalClock::_timeOffset = 0;
bool GlobalClock::_isRunning = false;

void GlobalClock::Start(long long initialTimestamp)
{
    _systemStartTime = GetCurrentSystemTimestamp();
    _baseTimestamp = initialTimestamp;
    _isRunning = true;
    _timeOffset = 0;
}

long long GlobalClock::GetCurrentTimestamp()
{
    if (!_isRunning)
    {
        //throw std::invalid_argument("时钟尚未启动，请先调用Start方法");
        return GetCurrentSystemTimestamp();
    }

    // 计算当前系统时间与启动时的差值，加上基准时间和偏移量
    long long currentSystemTime = GetCurrentSystemTimestamp();
    long long elapsedTime = currentSystemTime - _systemStartTime;
    return _baseTimestamp + elapsedTime + _timeOffset;
}

void GlobalClock::CorrectTime(long long newTimestamp)
{
    if (!_isRunning)
    {
        throw std::invalid_argument("时钟尚未启动，请先调用Start方法");
    }

    // 计算新的偏移量，使当前时间变为新的时间戳
    long long currentTime = GetCurrentTimestamp();
    _timeOffset = newTimestamp - currentTime;
}

long long GlobalClock::GetCurrentSystemTimestamp()
{
    using namespace std::chrono;

    // 获取当前系统时间（UTC）
    auto now = system_clock::now();

    // 转换为Unix时间戳（毫秒）
    auto duration = now.time_since_epoch();
    return duration_cast<milliseconds>(duration).count();
}

bool GlobalClock::IsRunning()
{
    return _isRunning;
}
