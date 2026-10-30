#ifndef XOVM_MATERIAL_CLOUD_PROVIDER_MANAGER_H_
#define XOVM_MATERIAL_CLOUD_PROVIDER_MANAGER_H_

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include "runtime/cloud_material/raw_socket_cloud_provider.h"

namespace xovm::material {

// Cloud provider manager for unified provider orchestration
// Implements fail-closed principle with mandatory validation
class CloudProviderManager {
 public:
  // Provider registration
  struct ProviderRegistration {
    uint32_t provider_id;
    RawSocketCloudProvider::ConnectionConfig config;
    bool is_primary;  // primary provider for failover
  };

  // Provider status
  enum class ProviderStatus {
    Healthy,
    Degraded,
    Unavailable,
    Unknown
  };

  // Provider health check result
  struct HealthCheckResult {
    uint32_t provider_id;
    ProviderStatus status;
    uint32_t latency_ms;
    uint32_t failed_attempts;
  };

  // Create manager with initial providers
  static std::optional<CloudProviderManager> create(
      const std::vector<ProviderRegistration>& registrations);

  // Register new provider
  bool registerProvider(const ProviderRegistration& registration);

  // Send message to primary provider
  bool sendMessage(const std::vector<uint8_t>& payload);

  // Send message to specific provider
  bool sendToProvider(uint32_t provider_id, const std::vector<uint8_t>& payload);

  // Receive message from active provider
  std::optional<std::vector<uint8_t>> receiveMessage();

  // Get provider status
  std::optional<ProviderStatus> getProviderStatus(uint32_t provider_id) const;

  // Get all provider statuses
  std::vector<HealthCheckResult> getAllProviderStatuses() const;

  // Perform health check on specific provider
  bool performHealthCheck(uint32_t provider_id);

  // Failover to next available provider
  bool failoverToNextProvider();

  // Get current active provider
  std::optional<uint32_t> getActiveProvider() const {
    return active_provider_;
  }

  // Get provider count
  uint32_t getProviderCount() const { return providers_.size(); }

 private:
  CloudProviderManager(
      const std::vector<ProviderRegistration>& registrations)
      : active_provider_(std::nullopt), health_check_counter_(0) {}

  std::map<uint32_t, RawSocketCloudProvider::ConnectionConfig> providers_;
  std::map<uint32_t, ProviderStatus> provider_statuses_;
  std::map<uint32_t, uint32_t> failed_attempts_;
  std::optional<uint32_t> active_provider_;
  uint32_t health_check_counter_;

  // Helper: validate registration
  static bool validateRegistration(const ProviderRegistration& registration);

  // Helper: find next available provider
  std::optional<uint32_t> findNextAvailableProvider();

  // Helper: update provider status
  void updateProviderStatus(uint32_t provider_id, ProviderStatus status);

  // Helper: check if provider is available
  bool isProviderAvailable(uint32_t provider_id) const;

  // No copy
  CloudProviderManager(const CloudProviderManager&) = delete;
  CloudProviderManager& operator=(const CloudProviderManager&) = delete;
};

}  // namespace xovm::material

#endif  // XOVM_MATERIAL_CLOUD_PROVIDER_MANAGER_H_
