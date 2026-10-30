#include <cassert>
#include <cstdint>

#include "runtime/cloud_material/chaff_scheduler_optimized.h"

namespace xovm::material::test {

bool testChaffSchedulerCreation() {
    xovm::material::ChaffSchedulerOptimized::WindowConfig config;
    config.total_windows = 100;
    config.chaff_percentage = 20;
    config.cache_line_size = 64;
    config.max_precomputed_size = 10000;
    
    auto scheduler = xovm::material::ChaffSchedulerOptimized::create(config);
    assert(scheduler.has_value() && "Failed to create scheduler");
    
    return true;
}

bool testChaffSchedulerValidation() {
    xovm::material::ChaffSchedulerOptimized::WindowConfig config;
    config.total_windows = 0;  // invalid
    config.chaff_percentage = 20;
    config.cache_line_size = 64;
    config.max_precomputed_size = 10000;
    
    auto scheduler = xovm::material::ChaffSchedulerOptimized::create(config);
    assert(!scheduler.has_value() && "Should reject invalid total_windows");
    
    // Test invalid chaff percentage
    config.total_windows = 100;
    config.chaff_percentage = 101;  // invalid
    scheduler = xovm::material::ChaffSchedulerOptimized::create(config);
    assert(!scheduler.has_value() && "Should reject invalid chaff_percentage");
    
    // Test invalid cache line size
    config.chaff_percentage = 20;
    config.cache_line_size = 0;  // invalid
    scheduler = xovm::material::ChaffSchedulerOptimized::create(config);
    assert(!scheduler.has_value() && "Should reject invalid cache_line_size");
    
    return true;
}

bool testChaffSchedulerExecution() {
    xovm::material::ChaffSchedulerOptimized::WindowConfig config;
    config.total_windows = 50;
    config.chaff_percentage = 20;  // 10 chaff, 40 real
    config.cache_line_size = 64;
    config.max_precomputed_size = 10000;
    
    auto scheduler = xovm::material::ChaffSchedulerOptimized::create(config);
    assert(scheduler.has_value());
    
    int real_windows = 0;
    int chaff_windows = 0;
    
    // Consume all windows
    while (!scheduler->isComplete()) {
        auto window = scheduler->nextWindow();
        if (window.has_value()) {
            real_windows++;
        }
        
        auto chaff = scheduler->nextChaffWindow();
        if (chaff.has_value()) {
            chaff_windows++;
        }
    }
    
    // Verify counts: approximately 40 real, 10 chaff
    assert(real_windows >= 38 && real_windows <= 42 && 
           "Real window count should be around 40");
    assert(chaff_windows >= 8 && chaff_windows <= 12 && 
           "Chaff window count should be around 10");
    
    return true;
}

bool testChaffSchedulerReset() {
    xovm::material::ChaffSchedulerOptimized::WindowConfig config;
    config.total_windows = 30;
    config.chaff_percentage = 30;
    config.cache_line_size = 64;
    config.max_precomputed_size = 10000;
    
    auto scheduler = xovm::material::ChaffSchedulerOptimized::create(config);
    assert(scheduler.has_value());
    
    // Schedule some windows
    scheduler->nextWindow();
    scheduler->nextWindow();
    assert(scheduler->scheduledCount() == 2);
    
    // Reset
    scheduler->reset();
    assert(scheduler->scheduledCount() == 0 && "Count should reset to 0");
    assert(!scheduler->isComplete() && "Should not be complete after reset");
    
    return true;
}

bool testChaffSchedulerHighPercentage() {
    xovm::material::ChaffSchedulerOptimized::WindowConfig config;
    config.total_windows = 100;
    config.chaff_percentage = 99;  // mostly chaff
    config.cache_line_size = 64;
    config.max_precomputed_size = 10000;
    
    auto scheduler = xovm::material::ChaffSchedulerOptimized::create(config);
    assert(scheduler.has_value());
    
    // Should still create valid scheduler
    int total = 0;
    while (!scheduler->isComplete() && total < 1000) {
        scheduler->nextWindow();
        scheduler->nextChaffWindow();
        total++;
    }
    
    assert(scheduler->isComplete() && "Should consume all windows");
    
    return true;
}

}  // namespace xovm::material::test

extern "C" int runChaffSchedulerOptimizedTests() {
    using namespace xovm::material::test;
    
    int tests_passed = 0;
    int tests_failed = 0;
    
    if (testChaffSchedulerCreation()) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (testChaffSchedulerValidation()) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (testChaffSchedulerExecution()) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (testChaffSchedulerReset()) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (testChaffSchedulerHighPercentage()) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    return tests_failed == 0 ? 0 : 1;
}
