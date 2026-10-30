#include "runtime/cloud_material/cloud_provider_manager.h"

namespace xovm::material {

bool CloudProviderManager::validateRegistration(
    const ProviderRegistration& registration) {
  if (registration.provider_id == 0) {
    return false;
  }
  if (registration.config.remote_port == 0) {
    return false;
  }
  if (registration.config.connection_timeout == 0 ||
      registration.config.connection_timeout > 60000) {
    return false;
  }
  if (registration.config.max_retries == 0 ||
      registration.config.max_retries > 10) {
    return false;
  }
  if (registration.config.buffer_size == 0 ||
      registration.config.buffer_size > 1048576) {
    return false;
  }
  return true;
}

std::optional<uint32_t> CloudProviderManager::findNextAvailableProvider() {
  for (const auto& [provider_id, status] : provider_statuses_) {
    if (status == ProviderStatus::Healthy ||
        status == ProviderStatus::Degraded) {
      return provider_id;
    }
  }
  return std::nullopt;
}

void CloudProviderManager::updateProviderStatus(uint32_t provider_id,
                                                ProviderStatus status) {
  provider_statuses_[provider_id] = status;
  if (status != ProviderStatus::Healthy) {
    failed_attempts_[provider_id]++;
  } else {
    failed_attempts_[provider_id] = 0;
  }
}

bool CloudProviderManager::isProviderAvailable(uint32_t provider_id) const {
  auto it = provider_statuses_.find(provider_id);
  if (it == provider_statuses_.end()) {
    return false;
  }
  return it->second == ProviderStatus::Healthy ||
         it->second == ProviderStatus::Degraded;
}

std::optional<CloudProviderManager> CloudProviderManager::create(
    const std::vector<ProviderRegistration>& registrations) {
  if (registrations.empty()) {
    return std::nullopt;
  }

  CloudProviderManager manager(registrations);

  // Validate and register all providers
  uint32_t primary_count = 0;
  for (const auto& reg : registrations) {
    if (!validateRegistration(reg)) {
      return std::nullopt;
    }

    manager.providers_[reg.provider_id] = reg.config;
    manager.provider_statuses_[reg.provider_id] = ProviderStatus::Unknown;
    manager.failed_attempts_[reg.provider_id] = 0;

    if (reg.is_primary) {
      primary_count++;
      manager.active_provider_ = reg.provider_id;
    }
  }

  // Must have at least one primary provider
  if (primary_count != 1) {
    return std::nullopt;
  }

  return manager;
}

bool CloudProviderManager::registerProvider(
    const ProviderRegistration& registration) {
  if (!validateRegistration(registration)) {
    return false;
  }

  if (providers_.find(registration.provider_id) != providers_.end()) {
    return false;  // Provider already exists
  }

  providers_[registration.provider_id] = registration.config;
  provider_statuses_[registration.provider_id] = ProviderStatus::Unknown;
  failed_attempts_[registration.provider_id] = 0;

  return true;
}

bool CloudProviderManager::sendMessage(const std::vector<uint8_t>& payload) {
  if (!active_provider_.has_value()) {
    return false;
  }

  return sendToProvider(active_provider_.value(), payload);
}

bool CloudProviderManager::sendToProvider(uint32_t provider_id,
                                          const std::vector<uint8_t>& payload) {
  if (payload.empty() || payload.size() > 65536) {
    return false;
  }

  if (!isProviderAvailable(provider_id)) {
    return false;
  }

  auto it = providers_.find(provider_id);
  if (it == providers_.end()) {
    return false;
  }

  auto provider = RawSocketCloudProvider::create(it->second);
  if (!provider.has_value()) {
    updateProviderStatus(provider_id, ProviderStatus::Unavailable);
    return false;
  }

  if (!provider->sendMessage(payload)) {
    updateProviderStatus(provider_id, ProviderStatus::Degraded);
    provider->close();
    return false;
  }

  updateProviderStatus(provider_id, ProviderStatus::Healthy);
  provider->close();
  return true;
}

std::optional<std::vector<uint8_t>> CloudProviderManager::receiveMessage() {
  if (!active_provider_.has_value()) {
    return std::nullopt;
  }

  auto it = providers_.find(active_provider_.value());
  if (it == providers_.end()) {
    return std::nullopt;
  }

  auto provider = RawSocketCloudProvider::create(it->second);
  if (!provider.has_value()) {
    updateProviderStatus(active_provider_.value(),
                         ProviderStatus::Unavailable);
    return std::nullopt;
  }

  auto message = provider->receiveMessage();
  if (!message.has_value()) {
    updateProviderStatus(active_provider_.value(), ProviderStatus::Degraded);
    provider->close();
    return std::nullopt;
  }

  updateProviderStatus(active_provider_.value(), ProviderStatus::Healthy);
  provider->close();
  return message;
}

std::optional<ProviderStatus> CloudProviderManager::getProviderStatus(
    uint32_t provider_id) const {
  auto it = provider_statuses_.find(provider_id);
  if (it == provider_statuses_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::vector<CloudProviderManager::HealthCheckResult>
CloudProviderManager::getAllProviderStatuses() const {
  std::vector<HealthCheckResult> results;
  for (const auto& [provider_id, status] : provider_statuses_) {
    HealthCheckResult result;
    result.provider_id = provider_id;
    result.status = status;
    result.latency_ms = 0;  // TODO: measure actual latency
    result.failed_attempts = failed_attempts_.at(provider_id);
    results.push_back(result);
  }
  return results;
}

bool CloudProviderManager::performHealthCheck(uint32_t provider_id) {
  auto it = providers_.find(provider_id);
  if (it == providers_.end()) {
    return false;
  }

  auto provider = RawSocketCloudProvider::create(it->second);
  if (!provider.has_value()) {
    updateProviderStatus(provider_id, ProviderStatus::Unavailable);
    return false;
  }

  // Send health check ping
  std::vector<uint8_t> ping = {0xDE, 0xAD};
  if (!provider->sendMessage(ping)) {
    updateProviderStatus(provider_id, ProviderStatus::Unavailable);
    provider->close();
    return false;
  }

  auto response = provider->receiveMessage();
  if (!response.has_value()) {
    updateProviderStatus(provider_id, ProviderStatus::Degraded);
    provider->close();
    return false;
  }

  updateProviderStatus(provider_id, ProviderStatus::Healthy);
  provider->close();
  return true;
}

bool CloudProviderManager::failoverToNextProvider() {
  if (!active_provider_.has_value()) {
    return false;
  }

  auto next = findNextAvailableProvider();
  if (!next.has_value()) {
    return false;
  }

  active_provider_ = next;
  return true;
}

}  // namespace xovm::material
