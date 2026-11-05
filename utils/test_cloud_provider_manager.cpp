#include <cassert>
#include <cstdint>

#include "runtime/cloud_material/cloud_provider_manager.h"

namespace xovm::material::test {

bool testCloudProviderManagerCreation() {
  std::vector<xovm::material::CloudProviderManager::ProviderRegistration> regs;
  
  xovm::material::CloudProviderManager::ProviderRegistration reg;
  reg.provider_id = 1;
  reg.config.remote_ip = 0x7F000001;  // 127.0.0.1
  reg.config.remote_port = 8080;
  reg.config.connection_timeout = 5000;
  reg.config.max_retries = 3;
  reg.config.buffer_size = 65536;
  reg.is_primary = true;
  
  regs.push_back(reg);
  
  auto manager = xovm::material::CloudProviderManager::create(regs);
  assert(manager.has_value() && "Failed to create manager");
  assert(manager->getProviderCount() == 1);
  assert(manager->getActiveProvider().has_value());
  assert(manager->getActiveProvider().value() == 1);
  assert(manager->getProviderStatus(1) ==
         xovm::material::CloudProviderManager::ProviderStatus::Unknown);
  
  return true;
}

bool testCloudProviderManagerValidation() {
  std::vector<xovm::material::CloudProviderManager::ProviderRegistration> regs;
  
  // Empty registrations
  auto manager = xovm::material::CloudProviderManager::create(regs);
  assert(!manager.has_value() && "Should reject empty registrations");
  
  // Invalid: zero provider_id
  xovm::material::CloudProviderManager::ProviderRegistration reg;
  reg.provider_id = 0;
  reg.config.remote_ip = 0x7F000001;
  reg.config.remote_port = 8080;
  reg.config.connection_timeout = 5000;
  reg.config.max_retries = 3;
  reg.config.buffer_size = 65536;
  reg.is_primary = true;
  regs.push_back(reg);
  
  manager = xovm::material::CloudProviderManager::create(regs);
  assert(!manager.has_value() && "Should reject zero provider_id");
  
  // Invalid: no primary provider
  regs.clear();
  reg.provider_id = 1;
  reg.is_primary = false;
  regs.push_back(reg);
  
  manager = xovm::material::CloudProviderManager::create(regs);
  assert(!manager.has_value() && "Should reject no primary provider");
  
  return true;
}

bool testProviderRegistration() {
  std::vector<xovm::material::CloudProviderManager::ProviderRegistration> regs;
  
  xovm::material::CloudProviderManager::ProviderRegistration reg1;
  reg1.provider_id = 1;
  reg1.config.remote_ip = 0x7F000001;
  reg1.config.remote_port = 8080;
  reg1.config.connection_timeout = 5000;
  reg1.config.max_retries = 3;
  reg1.config.buffer_size = 65536;
  reg1.is_primary = true;
  regs.push_back(reg1);
  
  auto manager = xovm::material::CloudProviderManager::create(regs);
  assert(manager.has_value());
  
  // Register additional provider
  xovm::material::CloudProviderManager::ProviderRegistration reg2;
  reg2.provider_id = 2;
  reg2.config = reg1.config;
  reg2.config.remote_port = 8081;
  reg2.is_primary = false;
  
  assert(manager->registerProvider(reg2));
  assert(manager->getProviderCount() == 2);
  
  // Cannot register duplicate provider_id
  assert(!manager->registerProvider(reg2));
  
  return true;
}

bool testProviderStatus() {
  std::vector<xovm::material::CloudProviderManager::ProviderRegistration> regs;
  
  xovm::material::CloudProviderManager::ProviderRegistration reg;
  reg.provider_id = 1;
  reg.config.remote_ip = 0x7F000001;
  reg.config.remote_port = 8080;
  reg.config.connection_timeout = 5000;
  reg.config.max_retries = 3;
  reg.config.buffer_size = 65536;
  reg.is_primary = true;
  regs.push_back(reg);
  
  auto manager = xovm::material::CloudProviderManager::create(regs);
  assert(manager.has_value());
  
  // Initial status should be Unknown
  auto status = manager->getProviderStatus(1);
  assert(status.has_value());
  assert(status.value() == xovm::material::CloudProviderManager::ProviderStatus::Unknown);
  
  // Non-existent provider
  status = manager->getProviderStatus(999);
  assert(!status.has_value());
  
  return true;
}

bool testGetAllProviderStatuses() {
  std::vector<xovm::material::CloudProviderManager::ProviderRegistration> regs;
  
  for (uint32_t i = 1; i <= 3; ++i) {
    xovm::material::CloudProviderManager::ProviderRegistration reg;
    reg.provider_id = i;
    reg.config.remote_ip = 0x7F000001;
    reg.config.remote_port = 8080 + i;
    reg.config.connection_timeout = 5000;
    reg.config.max_retries = 3;
    reg.config.buffer_size = 65536;
    reg.is_primary = (i == 1);
    regs.push_back(reg);
  }
  
  auto manager = xovm::material::CloudProviderManager::create(regs);
  assert(manager.has_value());
  
  auto statuses = manager->getAllProviderStatuses();
  assert(statuses.size() == 3);
  
  for (const auto& health : statuses) {
    assert(health.provider_id >= 1 && health.provider_id <= 3);
    assert(health.failed_attempts == 0);
  }
  
  return true;
}

bool testMultiplePrimaryProviders() {
  std::vector<xovm::material::CloudProviderManager::ProviderRegistration> regs;
  
  // Two primary providers - should fail
  xovm::material::CloudProviderManager::ProviderRegistration reg1;
  reg1.provider_id = 1;
  reg1.config.remote_ip = 0x7F000001;
  reg1.config.remote_port = 8080;
  reg1.config.connection_timeout = 5000;
  reg1.config.max_retries = 3;
  reg1.config.buffer_size = 65536;
  reg1.is_primary = true;
  regs.push_back(reg1);
  
  xovm::material::CloudProviderManager::ProviderRegistration reg2;
  reg2.provider_id = 2;
  reg2.config = reg1.config;
  reg2.config.remote_port = 8081;
  reg2.is_primary = true;
  regs.push_back(reg2);
  
  auto manager = xovm::material::CloudProviderManager::create(regs);
  assert(!manager.has_value() && "Should reject multiple primary providers");
  
  return true;
}

}  // namespace xovm::material::test

extern "C" int runCloudProviderManagerTests() {
  using namespace xovm::material::test;
  
  int tests_passed = 0;
  int tests_failed = 0;
  
  if (testCloudProviderManagerCreation()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  if (testCloudProviderManagerValidation()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  if (testProviderRegistration()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  if (testProviderStatus()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  if (testGetAllProviderStatuses()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  if (testMultiplePrimaryProviders()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  return tests_failed == 0 ? 0 : 1;
}
