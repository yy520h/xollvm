#include "zone_wrapper.h"

#include "capability_client.h"
#include "vm_dispatch_value.h"

#include "ZoneHelper.h"
#include "Core/nlohmann/json.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <ctime>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <openssl/sha.h>

namespace {

struct ZoneState {
	std::unique_ptr<ZoneHelper> helper;
	std::mutex mutex;
	std::condition_variable wake;
	std::thread heartbeat;
	std::thread signalMonitor;
	std::string softwareId;
	std::string version;
	std::string encryptKey;
	std::string encryptIv;
	std::string algorithm;
	uint32_t heartbeatPeriod = 120;
	uint32_t offlineGrace = 180;
	std::atomic<bool> stop{false};
	std::atomic<bool> stopSignalMonitor{false};
	std::atomic<bool> shutdownStarted{false};
	bool automaticShutdown = true;
	bool loggedIn = false;
	bool leaseValid = false;
	std::unique_ptr<xollvm::CapabilityClient> capabilityClient;
	std::string capabilityOperation;
	std::string capabilityBuildManifest;
	std::string dispatchKey;
	std::string dispatchSignedBlob;
	std::string dispatchWindowId;
	std::chrono::steady_clock::time_point dispatchFetchedAt;
	uint32_t dispatchPrefetchSeconds = 50;
	uint32_t dispatchWindowSeconds = 60;
};

volatile std::sig_atomic_t g_shutdownSignal = 0;

// Demo capability verification key; production builds should provide their own public key.
constexpr const char* kDemoCapabilityPublicKey =
	"-----BEGIN PUBLIC KEY-----\n"
	"MCowBQYDK2VwAyEArrhx5s0tAMNxS8kBQyV9H4299tELRzP6mwVi4GrpXfw=\n"
	"-----END PUBLIC KEY-----\n";

ZoneState& state() {
	static ZoneState value;
	return value;
}

bool isHeartbeatSuccess(const ApiResponse& response) {
	return response.Code == "50010" || response.Code == "50090";
}

void stopHeartbeat(ZoneState& s) {
	s.stop.store(true, std::memory_order_release);
	s.wake.notify_all();
	if (s.heartbeat.joinable())
		s.heartbeat.join();
}

void signalHandler(int signalNumber) {
	if (g_shutdownSignal == 0)
		g_shutdownSignal = signalNumber;
}

void stopSignalMonitor(ZoneState& s) {
	s.stopSignalMonitor.store(true, std::memory_order_release);
	s.wake.notify_all();
	if (s.signalMonitor.joinable() &&
		s.signalMonitor.get_id() != std::this_thread::get_id())
		s.signalMonitor.join();
}

void runSignalMonitor(ZoneState* s) {
	for (;;) {
		if (s->stopSignalMonitor.load(std::memory_order_acquire))
			return;
		if (g_shutdownSignal != 0) {
			xollvm_zone_shutdown();
			std::_Exit(128 + g_shutdownSignal);
		}
		std::unique_lock<std::mutex> lock(s->mutex);
		s->wake.wait_for(lock, std::chrono::milliseconds(50));
	}
}

void registerAutomaticShutdown(ZoneState& s) {
	static std::once_flag atexitOnce;
	std::call_once(atexitOnce, [] {
		std::atexit([] { xollvm_zone_shutdown(); });
	});
	std::signal(SIGINT, signalHandler);
	std::signal(SIGTERM, signalHandler);
#if defined(SIGHUP)
	std::signal(SIGHUP, signalHandler);
#endif
	g_shutdownSignal = 0;
	s.stopSignalMonitor.store(false, std::memory_order_release);
	if (!s.signalMonitor.joinable())
		s.signalMonitor = std::thread(runSignalMonitor, &s);
}

void runHeartbeat(ZoneState* s) {
	while (!s->stop.load(std::memory_order_acquire)) {
		std::unique_lock<std::mutex> lock(s->mutex);
		uint32_t period = s->heartbeatPeriod;
		auto deadline = std::chrono::steady_clock::now() +
			std::chrono::duration_cast<std::chrono::steady_clock::duration>(
				std::chrono::seconds(period));
		s->wake.wait_until(lock, deadline);
		if (s->stop.load(std::memory_order_acquire))
			break;
		if (!s->helper || !s->loggedIn)
			continue;
		ZoneHelper* helper = s->helper.get();
		lock.unlock();
		ApiResponse response;
		const int requestResult = helper->HeartBeat(response);
		const bool ok = requestResult == 1 && isHeartbeatSuccess(response);
		lock.lock();
		if (s->stop.load(std::memory_order_acquire))
			break;
		s->leaseValid = ok;
	}
}

std::string randomHex(size_t bytes) {
	std::random_device rd;
	std::ostringstream out;
	out << std::hex << std::setfill('0');
	for (size_t i = 0; i < bytes; ++i)
		out << std::setw(2) << (rd() & 0xff);
	return out.str();
}

std::string makeGuardHash(const std::string& nonce,
	const std::string& softwareId, const std::string& version) {
	// 该摘要绑定本次挑战和当前构建配置；云端仍以签名结果为最终依据。
	std::hash<std::string> hash;
	const uint64_t a = hash(nonce + "|" + softwareId);
	const uint64_t b = hash(version + "|" + nonce);
	std::ostringstream out;
	out << std::hex << std::setfill('0') << std::setw(16) << a
		<< std::setw(16) << b << std::setw(16) << hash(nonce)
		<< std::setw(16) << hash(softwareId + version);
	return out.str();
}

// 构造 vm_dispatch 能力请求；字段与 xollvm_zone_capability_begin 保持一致，
// 额外加入 client_tick 供云端绑定到派发窗口。nonce 每次请求重新生成。
std::string buildDispatchRequestJson(const std::string& operation,
	const std::string& manifest) {
	ZoneState& s = state();
	const char* buildId = std::getenv("XOLLVM_ZONE_CAPABILITY_BUILD_ID");
	const char* deviceId = std::getenv("XOLLVM_ZONE_DEVICE_ID");
	const std::string buildIdValue = buildId && buildId[0] ? buildId : "";
	const std::string deviceIdValue = deviceId && deviceId[0] ? deviceId : "";
	std::string stateValue = s.capabilityClient ? s.capabilityClient->state() : std::string();
	if (stateValue.empty())
		stateValue = std::string(32, '0');
	nlohmann::json requestJson = {
		{"protocol", "capability_v1"},
		{"software_id", s.softwareId},
		{"version", s.version},
		{"build_id", buildIdValue},
		{"device_id", deviceIdValue},
		{"operation", operation},
		{"state", stateValue},
		{"client_nonce", randomHex(16)},
		{"request_id", randomHex(16)},
		{"client_time", static_cast<uint64_t>(std::time(nullptr))},
		{"client_tick", xollvm::readClientTick()},
		{"code_manifest", manifest},
		{"payload", ""}};
	return requestJson.dump();
}

// 解析可能被 Result.RetMsg 多层包裹的响应 JSON，返回指定字符串字段，失败返回空串。
// 解包逻辑与 xollvm_zone_capability_begin 的 4 层 Result.RetMsg 一致。
std::string extractJsonString(const std::string& encoded, const char* field) {
	nlohmann::json json;
	try {
		json = nlohmann::json::parse(encoded);
	} catch (const nlohmann::json::parse_error&) {
		return std::string();
	}
	for (unsigned int unwrapDepth = 0; unwrapDepth < 4; ++unwrapDepth) {
		const nlohmann::json* wrapped = nullptr;
		if (json.is_string()) {
			wrapped = &json;
		} else if (json.is_object() && json.contains("Result") && json["Result"].is_object() &&
			json["Result"].contains("RetMsg") && json["Result"]["RetMsg"].is_string()) {
			wrapped = &json["Result"]["RetMsg"];
		} else {
			break;
		}
		try {
			json = nlohmann::json::parse(wrapped->get<std::string>());
		} catch (const nlohmann::json::parse_error&) {
			return std::string();
		}
	}
	if (!json.is_object() || !json.contains(field) || !json[field].is_string())
		return std::string();
	return json[field].get<std::string>();
}

} // namespace

extern "C" int xollvm_zone_initialize(const char* software_id,
	const char* version, const char* encrypt_key, const char* encrypt_iv,
	const char* algorithm, const char* capability_key_id,
	uint32_t heartbeat_period_sec, uint32_t offline_grace_sec) {
	if (!software_id || !version || !encrypt_key || !encrypt_iv ||
		!algorithm || !capability_key_id ||
		software_id[0] == '\0' || version[0] == '\0' ||
		heartbeat_period_sec == 0 || offline_grace_sec == 0)
		return 0;
	ZoneState& s = state();
	stopHeartbeat(s);
	stopSignalMonitor(s);
	std::lock_guard<std::mutex> lock(s.mutex);
	s.helper.reset();
	s.helper = std::make_unique<ZoneHelper>(
		software_id, version, encrypt_key, encrypt_iv,
		eum_EncryptType::AES, eum_LoginType::Card,
		eum_AgreementType::HTTP, eum_NetworkRegion::ChinaDomestic);
	s.softwareId = software_id;
	s.version = version;
	s.encryptKey = encrypt_key;
	s.encryptIv = encrypt_iv;
	s.algorithm = algorithm;
	s.heartbeatPeriod = heartbeat_period_sec;
	s.offlineGrace = offline_grace_sec;
	s.loggedIn = false;
	s.leaseValid = false;
	s.capabilityClient.reset();
	s.capabilityOperation.clear();
	s.capabilityBuildManifest.clear();
	s.dispatchKey.clear();
	s.dispatchSignedBlob.clear();
	s.dispatchWindowId.clear();
	s.dispatchFetchedAt = std::chrono::steady_clock::time_point{};
	const char* capabilityOperation = std::getenv("XOLLVM_ZONE_CAPABILITY_OPERATION");
	const char* capabilityManifest = std::getenv("XOLLVM_ZONE_CAPABILITY_CODE_MANIFEST");
	const char* capabilityPublicKey = std::getenv("XOLLVM_ZONE_CAPABILITY_PUBLIC_KEY");
	const char* capabilityStatePath = std::getenv("XOLLVM_ZONE_CAPABILITY_STATE_PATH");
	const char* capabilityBuildId = std::getenv("XOLLVM_ZONE_CAPABILITY_BUILD_ID");
	const char* capabilityDeviceId = std::getenv("XOLLVM_ZONE_DEVICE_ID");
	const bool capabilityAlgorithm = std::string(algorithm) == "capability_v1";
	if (capabilityAlgorithm) {
		capabilityOperation = capabilityOperation && capabilityOperation[0]
			? capabilityOperation : "demo_sensitive_action";
		capabilityManifest = capabilityManifest && capabilityManifest[0]
			? capabilityManifest : "demo-code-manifest-v1";
		capabilityPublicKey = capabilityPublicKey && capabilityPublicKey[0]
			? capabilityPublicKey : kDemoCapabilityPublicKey;
		capabilityStatePath = capabilityStatePath && capabilityStatePath[0]
			? capabilityStatePath : "/data/local/tmp/xollvm_zone_capability.state";
		capabilityBuildId = capabilityBuildId && capabilityBuildId[0]
			? capabilityBuildId : "demo-build-v1";
		capabilityDeviceId = capabilityDeviceId && capabilityDeviceId[0]
			? capabilityDeviceId : "demo-device-v1";
	}
	if (capabilityOperation && capabilityManifest && capabilityPublicKey && capabilityStatePath &&
		capabilityBuildId && capabilityOperation[0] && capabilityManifest[0] &&
		capabilityPublicKey[0] && capabilityStatePath[0] && capabilityBuildId[0]) {
		xollvm::CapabilityClientConfig config;
		config.operation = capabilityOperation;
		config.build_manifest = capabilityManifest;
		config.public_key_pem = capabilityPublicKey;
		config.key_id = capability_key_id;
		config.state_path = capabilityStatePath;
		config.server_time = static_cast<uint64_t>(std::time(nullptr));
		s.capabilityClient = std::make_unique<xollvm::CapabilityClient>(std::move(config));
		setenv("XOLLVM_ZONE_CAPABILITY_OPERATION", capabilityOperation, 0);
		setenv("XOLLVM_ZONE_CAPABILITY_CODE_MANIFEST", capabilityManifest, 0);
		setenv("XOLLVM_ZONE_CAPABILITY_BUILD_ID", capabilityBuildId, 0);
		setenv("XOLLVM_ZONE_DEVICE_ID", capabilityDeviceId, 0);
		s.capabilityOperation = capabilityOperation;
		s.capabilityBuildManifest = capabilityManifest;
	}
	s.stop.store(false, std::memory_order_release);
	s.shutdownStarted.store(false, std::memory_order_release);
	return s.helper ? 1 : 0;
}

extern "C" void xollvm_zone_set_shutdown_mode(int automatic) {
	ZoneState& s = state();
	std::lock_guard<std::mutex> lock(s.mutex);
	s.automaticShutdown = automatic != 0;
}

extern "C" int xollvm_zone_login_card(const char* card) {
	ZoneState& s = state();
	std::lock_guard<std::mutex> lock(s.mutex);
	if (!s.helper)
		return 0;
	std::string runtimeCard;
	if (!card || card[0] == '\0') {
		std::cout << "Card: " << std::flush;
		if (!std::getline(std::cin, runtimeCard) || runtimeCard.empty())
			return 0;
		card = runtimeCard.c_str();
	}
	ApiResponse response;
	int requestResult = s.helper->LoginC(response, card, "", "");
	const bool acceptedCode = response.Code == "50005" ||
		response.Code == "50057";
	const bool acceptedStatus = response.Data.Run_status == "success" &&
		!response.Data.Token.empty();
	if (requestResult != 1 || (!acceptedCode && !acceptedStatus) ||
		response.Data.Token.empty()) {
		std::cerr << "Zone card business login rejected: request="
			<< requestResult << ", run_status=" << response.Data.Run_status
			<< ", data_status=" << response.Data.Status
			<< ", code=" << response.Code << ", message="
			<< response.Message << ", data_message="
			<< response.Data.Message << '\n';
		return 0;
	}
	s.loggedIn = true;
	s.leaseValid = false;
	if (s.automaticShutdown)
		registerAutomaticShutdown(s);
	return 1;
}

extern "C" int xollvm_zone_first_heartbeat(void) {
	ZoneState& s = state();
	std::unique_lock<std::mutex> lock(s.mutex);
	if (!s.helper || !s.loggedIn)
		return 0;
	ApiResponse response;
	const int heartbeatResult = s.helper->HeartBeat(response);
	if (heartbeatResult != 1 || !isHeartbeatSuccess(response)) {
		std::cerr << "Zone heartbeat request failed: result=" << heartbeatResult
			<< ", status=" << response.Status << ", code=" << response.Code
			<< ", message=" << response.Message << ", data_message="
			<< response.Data.Message << '\n';
		return 0;
	}
	if (!s.algorithm.empty() && s.algorithm != "capability_v1") {
		ApiResponse algorithmResponse;
		int requestResult = s.helper->GetAntiAlgorithmValue(
			algorithmResponse, s.algorithm, "");
		if (requestResult != 1) {
			std::cerr << "Zone cloud algorithm request failed: status="
				<< algorithmResponse.Status << ", code="
				<< algorithmResponse.Code << ", message="
				<< algorithmResponse.Message << '\n';
			return 0;
		}
		std::cerr << "Zone cloud algorithm response: status="
			<< algorithmResponse.Status << ", code=" << algorithmResponse.Code
			<< ", message=" << algorithmResponse.Message << ", run_status="
			<< algorithmResponse.Data.Run_status << ", data_message="
			<< algorithmResponse.Data.Message << ", value_size="
			<< algorithmResponse.Data.value.size() << '\n';
		if (algorithmResponse.Status != "200" ||
			algorithmResponse.Code != "70037" ||
			algorithmResponse.Data.value.empty()) {
			std::cerr << "Zone cloud algorithm rejected: status="
				<< algorithmResponse.Status << ", code="
				<< algorithmResponse.Code << ", message="
				<< algorithmResponse.Message << ", run_status="
				<< algorithmResponse.Data.Run_status << ", data_message="
				<< algorithmResponse.Data.Message << ", value_size="
				<< algorithmResponse.Data.value.size() << '\n';
			return 0;
		}
	}
	s.leaseValid = true;
	if (!s.heartbeat.joinable())
		s.heartbeat = std::thread(runHeartbeat, &s);
	return 1;
}

extern "C" int xollvm_zone_refresh_lease(void) {
	ZoneState& s = state();
	std::lock_guard<std::mutex> lock(s.mutex);
	if (!s.helper || !s.loggedIn)
		return 0;
	ApiResponse response;
	s.leaseValid = s.helper->HeartBeat(response) == 1 &&
		isHeartbeatSuccess(response);
	return s.leaseValid ? 1 : 0;
}

extern "C" int xollvm_zone_require(const char* capability) {
	ZoneState& s = state();
	std::lock_guard<std::mutex> lock(s.mutex);
	const bool leaseReady = s.helper && s.loggedIn && s.leaseValid && capability && capability[0] != '\0';
	const bool capabilityReady = !s.capabilityClient ||
		s.capabilityClient->require(capability, static_cast<uint64_t>(std::time(nullptr)));
	return leaseReady && capabilityReady;
}

extern "C" int xollvm_zone_capability_begin(const char* operation, const char* payload) {
	ZoneState& s = state();
	std::unique_lock<std::mutex> lock(s.mutex);
	if (!s.helper || !s.loggedIn || !s.leaseValid || !s.capabilityClient || !operation || !payload ||
		operation[0] == '\0' || s.capabilityOperation != operation ||
		s.algorithm != "capability_v1")
		return 0;
	ZoneHelper* helper = s.helper.get();
	xollvm::CapabilityClient* client = s.capabilityClient.get();
	const std::string softwareId = s.softwareId;
	const std::string version = s.version;
	const std::string manifest = s.capabilityBuildManifest;
	const std::string stateValue = client->state();
	const char* buildId = std::getenv("XOLLVM_ZONE_CAPABILITY_BUILD_ID");
	const char* deviceId = std::getenv("XOLLVM_ZONE_DEVICE_ID");
	if (!buildId || !deviceId || !buildId[0] || !deviceId[0])
		return 0;
	const std::string buildIdValue = buildId;
	const std::string deviceIdValue = deviceId;
	lock.unlock();
	xollvm::CapabilityRequest capabilityRequest;
	capabilityRequest.protocol = "capability_v1";
	capabilityRequest.software_id = softwareId;
	capabilityRequest.version = version;
	capabilityRequest.build_id = buildIdValue;
	capabilityRequest.device_id = deviceIdValue;
	capabilityRequest.operation = operation;
	capabilityRequest.state = stateValue;
	if (capabilityRequest.state.empty())
		capabilityRequest.state = std::string(32, '0');
	capabilityRequest.client_nonce = randomHex(16);
	capabilityRequest.request_id = randomHex(16);
	capabilityRequest.client_time = static_cast<uint64_t>(std::time(nullptr));
	capabilityRequest.code_manifest = manifest;
	capabilityRequest.payload = payload;
	const std::string canonicalRequest = xollvm::canonicalizeCapabilityRequest(capabilityRequest);
	unsigned char requestDigest[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char*>(canonicalRequest.data()),
		canonicalRequest.size(), requestDigest);
	static const char hex[] = "0123456789abcdef";
	std::string requestHash;
	requestHash.resize(SHA256_DIGEST_LENGTH * 2);
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		requestHash[i * 2] = hex[requestDigest[i] >> 4];
		requestHash[i * 2 + 1] = hex[requestDigest[i] & 0x0f];
	}
	unsigned char deviceDigest[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char*>(deviceIdValue.data()), deviceIdValue.size(), deviceDigest);
	std::string deviceIdHash;
	deviceIdHash.resize(SHA256_DIGEST_LENGTH * 2);
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		deviceIdHash[i * 2] = hex[deviceDigest[i] >> 4];
		deviceIdHash[i * 2 + 1] = hex[deviceDigest[i] & 0x0f];
	}
	nlohmann::json requestJson = {
		{"protocol", capabilityRequest.protocol}, {"software_id", capabilityRequest.software_id},
		{"version", capabilityRequest.version}, {"build_id", capabilityRequest.build_id},
		{"device_id", capabilityRequest.device_id}, {"operation", capabilityRequest.operation},
		{"state", capabilityRequest.state}, {"client_nonce", capabilityRequest.client_nonce},
		{"request_id", capabilityRequest.request_id}, {"client_time", capabilityRequest.client_time},
		{"code_manifest", capabilityRequest.code_manifest}, {"payload", capabilityRequest.payload}};
	ApiResponse response;
	const int requestResult = helper->GetAntiAlgorithmValue(
		response, "capability_v1", requestJson.dump());
	if (requestResult != 1 || response.Data.value.empty()) {
		std::cerr << "Zone capability request failed\n";
		return 0;
	}
	nlohmann::json json;
	try {
		json = nlohmann::json::parse(response.Data.value);
	} catch (const nlohmann::json::parse_error&) {
		std::cerr << "Zone capability rejected: malformed response JSON\n";
		return 0;
	}
	for (unsigned int unwrapDepth = 0; unwrapDepth < 4; ++unwrapDepth) {
		const nlohmann::json* encoded = nullptr;
		if (json.is_string()) {
			encoded = &json;
		} else if (json.is_object() && json.contains("Result") && json["Result"].is_object() &&
			json["Result"].contains("RetMsg") && json["Result"]["RetMsg"].is_string()) {
			encoded = &json["Result"]["RetMsg"];
		} else {
			break;
		}
		try {
			json = nlohmann::json::parse(encoded->get<std::string>());
		} catch (const nlohmann::json::parse_error&) {
			std::cerr << "Zone capability rejected: malformed wrapped response JSON\n";
			return 0;
		}
	}
	if (!json.is_object()) {
		std::cerr << "Zone capability rejected: response root is not an object\n";
		return 0;
	}
	const auto hasFieldType = [&json](const char* field, nlohmann::json::value_t expected) {
		if (!json.contains(field) || json[field].type() != expected) {
			std::cerr << "Zone capability rejected: response validation failed\n";
			return false;
		}
		return true;
	};
	if (!json.contains("protocol") || !json["protocol"].is_number()) {
		std::cerr << "Zone capability rejected: response validation failed\n";
		return 0;
	}
	if (!hasFieldType("ok", nlohmann::json::value_t::boolean) ||
		!hasFieldType("operation", nlohmann::json::value_t::string) ||
		!hasFieldType("request_hash", nlohmann::json::value_t::string) ||
		!hasFieldType("device_id_hash", nlohmann::json::value_t::string) ||
		!hasFieldType("next_state", nlohmann::json::value_t::string) ||
		!hasFieldType("vm_value", nlohmann::json::value_t::string))
		return 0;
	for (const char* field : {"server_time", "issued_at", "expires_at", "policy_version"}) {
		if (!json.contains(field) || (!json[field].is_number_unsigned() && !json[field].is_number_integer())) {
			std::cerr << "Zone capability rejected: response validation failed\n";
			return 0;
		}
	}
	if (!hasFieldType("key_id", nlohmann::json::value_t::string) ||
		!hasFieldType("signature", nlohmann::json::value_t::string))
		return 0;
	try {
		xollvm::CapabilityResponse capabilityResponse;
		capabilityResponse.protocol = json.at("protocol").get<uint32_t>();
		capabilityResponse.ok = json.at("ok").get<bool>();
		capabilityResponse.operation = json.at("operation").get<std::string>();
		capabilityResponse.request_hash = json.at("request_hash").get<std::string>();
		capabilityResponse.device_id_hash = json.at("device_id_hash").get<std::string>();
		capabilityResponse.next_state = json.at("next_state").get<std::string>();
		capabilityResponse.vm_value = json.at("vm_value").get<std::string>();
		capabilityResponse.server_time = json.at("server_time").get<uint64_t>();
		capabilityResponse.issued_at = json.at("issued_at").get<uint64_t>();
		capabilityResponse.expires_at = json.at("expires_at").get<uint64_t>();
		capabilityResponse.policy_version = json.at("policy_version").get<uint32_t>();
		capabilityResponse.key_id = json.at("key_id").get<std::string>();
		capabilityResponse.signature = json.at("signature").get<std::string>();
		if (capabilityResponse.request_hash.empty()) {
			std::cerr << "Zone capability rejected: empty request_hash\n";
			return 0;
		}
		lock.lock();
		if (s.capabilityClient.get() != client || !s.loggedIn || !s.leaseValid) {
			lock.unlock();
			return 0;
		}
		const int accepted = client->acceptResponse(
			capabilityResponse, requestHash, deviceIdHash) ? 1 : 0;
		lock.unlock();
		if (!accepted)
			std::cerr << "Zone capability rejected: verification or binding failed\n";
		return accepted;
	} catch (const nlohmann::json::exception&) {
		std::cerr << "Zone capability rejected: response conversion failed\n";
		return 0;
	}
}

extern "C" int xollvm_zone_capability_require(const char* operation,
	const char* request_hash) {
	ZoneState& s = state();
	std::lock_guard<std::mutex> lock(s.mutex);
	return s.capabilityClient && s.leaseValid && operation && request_hash &&
		s.capabilityClient->require(operation, static_cast<uint64_t>(std::time(nullptr))) ? 1 : 0;
}

extern "C" int xollvm_zone_capability_seed(const char* operation,
	const char* code_manifest, char* out_hex, uint32_t out_size) {
	ZoneState& s = state();
	std::lock_guard<std::mutex> lock(s.mutex);
	if (!s.capabilityClient || !operation || !code_manifest || !out_hex || out_size < 65 ||
		!s.capabilityClient->require(operation, static_cast<uint64_t>(std::time(nullptr))))
		return 0;
	const xollvm::CapabilityResponse& response = s.capabilityClient->response();
	const std::string input = std::string("seed\0", 5) + code_manifest + "\0" + operation +
		"\0" + response.vm_value;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);
	static const char hex[] = "0123456789abcdef";
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		out_hex[i * 2] = hex[digest[i] >> 4];
		out_hex[i * 2 + 1] = hex[digest[i] & 0x0f];
	}
	out_hex[64] = '\0';
	return 1;
}

extern "C" void xollvm_zone_capability_clear(void) {
	ZoneState& s = state();
	std::lock_guard<std::mutex> lock(s.mutex);
	s.capabilityClient.reset();
}

extern "C" int xollvm_zone_vm_dispatch_refresh(void) {
	ZoneState& s = state();
	std::unique_lock<std::mutex> lock(s.mutex);
	if (!s.helper || !s.loggedIn || !s.capabilityClient || s.algorithm != "capability_v1")
		return 0;
	const std::string operation = "vm_dispatch";
	const std::string manifest = s.capabilityBuildManifest;
	ZoneHelper* helper = s.helper.get();
	lock.unlock();
	ApiResponse response;
	if (helper->GetAntiAlgorithmValue(response, "capability_v1", buildDispatchRequestJson(operation, manifest)) != 1 ||
		response.Data.value.empty())
		return 0;
	const std::string signedBlob = extractJsonString(response.Data.value, "dispatch_blob");
	const std::string windowId = extractJsonString(response.Data.value, "window_id");
	if (signedBlob.empty() || windowId.empty())
		return 0;
	const uint64_t tick = xollvm::readClientTick();
	const std::string key = xollvm::deriveDispatchKey(signedBlob, tick);
	lock.lock();
	s.dispatchSignedBlob = signedBlob;
	s.dispatchWindowId = windowId;
	s.dispatchKey = key;
	s.dispatchFetchedAt = std::chrono::steady_clock::now();
	return 1;
}

extern "C" char* xollvm_zone_vm_dispatch_value(void) {
	ZoneState& s = state();
	std::lock_guard<std::mutex> lock(s.mutex);
	if (s.dispatchKey.empty())
		return nullptr;
	if (s.algorithm != "capability_v1")
		return nullptr;
	const uint64_t tick = xollvm::readClientTick();
	static thread_local std::string value;
	value = xollvm::deriveDispatchKey(s.dispatchSignedBlob, tick);
	return const_cast<char*>(value.c_str());
}

extern "C" void xollvm_zone_shutdown(void) {
	ZoneState& s = state();
	bool expected = false;
	if (!s.shutdownStarted.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel))
		return;
	stopHeartbeat(s);
	stopSignalMonitor(s);
	std::lock_guard<std::mutex> lock(s.mutex);
	if (s.helper && s.loggedIn) {
		ApiResponse response;
		const int result = s.helper->Logout(response);
		std::cerr << "Zone logout response: request=" << result
			<< ", status=" << response.Status << ", code=" << response.Code
			<< ", message=" << response.Message << '\n';
	}
	s.leaseValid = false;
	s.loggedIn = false;
	s.helper.reset();
}
