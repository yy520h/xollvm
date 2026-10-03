#include "zone_wrapper.h"

#include "capability_client.h"
#include "vm_dispatch_value.h"

#include "ZoneHelper.h"
#include "Core/nlohmann/json.hpp"
#include "Core/base64.h"

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
	std::string dispatchNonce;
	std::string dispatchWindowId;
	// 云值驱动 dispatch：原始 32 字节 V（云端针对当前 window 搜索，使
	// HMAC(V, window) & MASK == 0）。由 refresh 解析 dispatch_v 填入，
	// 供 cloud_value_manager 计算 dispatch offset。
	std::string dispatchV;
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

// capability 状态文件的默认路径：优先选一个可写目录。
// `/data/local/tmp` 在 Termux 下不可写，会导致第一次验证写状态失败。
const std::string& defaultCapabilityStatePath() {
	static const std::string path = []() -> std::string {
		const char* home = std::getenv("HOME");
		if (home && home[0])
			return std::string(home) + "/xollvm_zone_capability.state";
		const char* tmp = std::getenv("TMPDIR");
		if (tmp && tmp[0])
			return std::string(tmp) + "/xollvm_zone_capability.state";
		return "/data/local/tmp/xollvm_zone_capability.state";
	}();
	return path;
}

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

[[maybe_unused]] std::string makeGuardHash(const std::string& nonce,
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

// 从响应 Data.value 中逐层解开 Result.RetMsg 包裹（最多 4 层），
// 返回最内层的 JSON；解析失败返回 false。capability_begin 与 dispatch 共用此函数。
bool unwrapResponseJson(const std::string& encoded, nlohmann::json* out) {
	nlohmann::json json;
	try {
		json = nlohmann::json::parse(encoded);
	} catch (const nlohmann::json::parse_error&) {
		return false;
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
			return false;
		}
	}
	*out = std::move(json);
	return true;
}

// 从已解包的 JSON 中取指定字符串字段，缺失或类型不符返回空串。
std::string jsonStringField(const nlohmann::json& json, const char* field) {
	if (!json.is_object() || !json.contains(field) || !json[field].is_string())
		return std::string();
	return json[field].get<std::string>();
}

// 解析可能被 Result.RetMsg 多层包裹的响应 JSON，返回指定字符串字段，失败返回空串。
[[maybe_unused]] std::string extractJsonString(const std::string& encoded, const char* field) {
	nlohmann::json json;
	if (!unwrapResponseJson(encoded, &json))
		return std::string();
	return jsonStringField(json, field);
}

// 将 CapabilityRequest 序列化为与云端一致的 JSON 请求体；字段定义只此一处，
// xollvm_zone_capability_begin 与 vm_dispatch 请求共用，避免 schema 漂移。
nlohmann::json capabilityRequestJson(const xollvm::CapabilityRequest& request) {
	return {
		{"protocol", request.protocol}, {"software_id", request.software_id},
		{"version", request.version}, {"build_id", request.build_id},
		{"device_id", request.device_id}, {"operation", request.operation},
		{"state", request.state}, {"client_nonce", request.client_nonce},
		{"request_id", request.request_id}, {"client_time", request.client_time},
		{"code_manifest", request.code_manifest}, {"payload", request.payload}};
}

// 网络调用前在锁内快照的 ZoneState 字段，网络期间只读快照，避免无锁访问。
struct DispatchSnapshot {
	std::string softwareId;
	std::string version;
	std::string manifest;
	std::string clientState;
	std::string buildId;
	std::string deviceId;
};

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
	s.dispatchNonce.clear();
	s.dispatchWindowId.clear();
	s.dispatchV.clear();
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
			? capabilityStatePath : defaultCapabilityStatePath().c_str();
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
	ApiResponse response;
	const int requestResult = helper->GetAntiAlgorithmValue(
		response, "capability_v1", capabilityRequestJson(capabilityRequest).dump());
	if (requestResult != 1 || response.Data.value.empty()) {
		std::cerr << "Zone capability request failed\n";
		return 0;
	}
	nlohmann::json json;
	if (!unwrapResponseJson(response.Data.value, &json)) {
		std::cerr << "Zone capability rejected: malformed response JSON\n";
		return 0;
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
		// 云值驱动 dispatch 字段：必须参与签名 canonicalization，漏掉会让
		// 客户端重算的规范化串与云端签名时不一致 -> 验签失败。
		capabilityResponse.window_id = json.value("window_id", std::string());
		capabilityResponse.dispatch_blob = json.value("dispatch_blob", std::string());
		capabilityResponse.dispatch_v = json.value("dispatch_v", std::string());
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
	if (!s.helper || !s.loggedIn || !s.leaseValid || !s.capabilityClient ||
		s.algorithm != "capability_v1")
		return 0;
	// 网络调用前在锁内快照所有需要的状态，解锁后只读快照。
	xollvm::CapabilityClient* client = s.capabilityClient.get();
	DispatchSnapshot snapshot;
	snapshot.softwareId = s.softwareId;
	snapshot.version = s.version;
	snapshot.manifest = s.capabilityBuildManifest;
	snapshot.clientState = client->state();
	const char* buildId = std::getenv("XOLLVM_ZONE_CAPABILITY_BUILD_ID");
	const char* deviceId = std::getenv("XOLLVM_ZONE_DEVICE_ID");
	snapshot.buildId = buildId && buildId[0] ? buildId : "";
	snapshot.deviceId = deviceId && deviceId[0] ? deviceId : "";
	const std::string operation = "vm_dispatch";
	ZoneHelper* helper = s.helper.get();
	lock.unlock();

	// 构造请求并计算 requestHash / deviceIdHash（与 capability_begin 相同的口径）
	xollvm::CapabilityRequest capabilityRequest;
	capabilityRequest.protocol = "capability_v1";
	capabilityRequest.software_id = snapshot.softwareId;
	capabilityRequest.version = snapshot.version;
	capabilityRequest.build_id = snapshot.buildId;
	capabilityRequest.device_id = snapshot.deviceId;
	capabilityRequest.operation = operation;
	capabilityRequest.state = snapshot.clientState.empty()
		? std::string(32, '0') : snapshot.clientState;
	capabilityRequest.client_nonce = randomHex(16);
	capabilityRequest.request_id = randomHex(16);
	capabilityRequest.client_time = static_cast<uint64_t>(std::time(nullptr));
	capabilityRequest.code_manifest = snapshot.manifest;
	capabilityRequest.payload = "";

	const std::string canonicalRequest =
		xollvm::canonicalizeCapabilityRequest(capabilityRequest);
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
	std::string deviceIdHash;
	{
		unsigned char deviceDigest[SHA256_DIGEST_LENGTH];
		SHA256(reinterpret_cast<const unsigned char*>(snapshot.deviceId.data()),
			snapshot.deviceId.size(), deviceDigest);
		deviceIdHash.resize(SHA256_DIGEST_LENGTH * 2);
		for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
			deviceIdHash[i * 2] = hex[deviceDigest[i] >> 4];
			deviceIdHash[i * 2 + 1] = hex[deviceDigest[i] & 0x0f];
		}
	}

	// 发起网络请求
	nlohmann::json requestJson = capabilityRequestJson(capabilityRequest);
	requestJson["client_tick"] = xollvm::readClientTick();
	std::string requestNonce = capabilityRequest.client_nonce;
	ApiResponse response;
	int gav = helper->GetAntiAlgorithmValue(response, "capability_v1",
			requestJson.dump());
#ifdef XOLLVM_ZONE_DEBUG_PKT
	std::fprintf(stderr, "[Zone][vmdisp] GetAntiAlgorithmValue rc=%d value.size=%zu\n",
		gav, response.Data.value.size());
	std::fprintf(stderr, "[Zone][vmdisp] raw value:\n%s\n", response.Data.value.c_str());
#endif
	if (gav != 1 || response.Data.value.empty())
		return 0;

	// 解析完整 JSON 响应为 CapabilityResponse，供 verifyDispatchResponse 校验
	nlohmann::json json;
	if (!unwrapResponseJson(response.Data.value, &json)) {
		std::fprintf(stderr, "[Zone][vmdisp] malformed response JSON\n");
		return 0;
	}
	if (!json.is_object())
		return 0;
	try {
		xollvm::CapabilityResponse capabilityResponse;
		capabilityResponse.protocol = json.value("protocol", 0u);
		capabilityResponse.ok = json.value("ok", false);
		capabilityResponse.operation = json.value("operation", std::string());
		capabilityResponse.request_hash = json.value("request_hash", std::string());
		capabilityResponse.device_id_hash = json.value("device_id_hash", std::string());
		capabilityResponse.next_state = json.value("next_state", std::string());
		capabilityResponse.vm_value = json.value("vm_value", std::string());
		capabilityResponse.server_time = json.value("server_time", uint64_t{0});
		capabilityResponse.issued_at = json.value("issued_at", uint64_t{0});
		capabilityResponse.expires_at = json.value("expires_at", uint64_t{0});
		capabilityResponse.policy_version = json.value("policy_version", 0u);
		capabilityResponse.key_id = json.value("key_id", std::string());
		capabilityResponse.signature = json.value("signature", std::string());
		capabilityResponse.window_id = json.value("window_id", std::string());
		capabilityResponse.dispatch_blob = json.value("dispatch_blob", std::string());
		capabilityResponse.dispatch_v = json.value("dispatch_v", std::string());

		// 修复 #7：vm_dispatch 响应必须走验签/request/device/有效期绑定校验，
		// 不能把未验证的 dispatch_v 写入全局状态。
		if (!client->verifyDispatchResponse(capabilityResponse,
				requestHash, deviceIdHash)) {
			std::fprintf(stderr,
				"[Zone][vmdisp] dispatch response verification failed\n");
			return 0;
		}

		const std::string signedBlob = capabilityResponse.dispatch_blob;
		const std::string windowId = capabilityResponse.window_id;
		const std::string vB64 = capabilityResponse.dispatch_v;
		if (windowId.empty() || (signedBlob.empty() && vB64.empty()))
			return 0;
		std::string vRaw;
		if (!vB64.empty()) {
			vRaw = base64_decode(vB64);
			if (vRaw.size() != 32)
				vRaw.clear();
		}
		std::string key;
		if (!signedBlob.empty())
			key = xollvm::deriveDispatchKey(signedBlob, xollvm::readClientTick());
		lock.lock();
		// 回写前复核 generation：客户端未被替换、仍登录且租约有效，否则丢弃结果。
		if (s.capabilityClient.get() != client || !s.loggedIn || !s.leaseValid) {
			lock.unlock();
			return 0;
		}
		if (!signedBlob.empty()) {
			s.dispatchSignedBlob = signedBlob;
			s.dispatchKey = key;
		}
		if (!vRaw.empty())
			s.dispatchV = vRaw;
		s.dispatchNonce = requestNonce;
		s.dispatchWindowId = windowId;
		s.dispatchFetchedAt = std::chrono::steady_clock::now();
		return 1;
	} catch (const nlohmann::json::exception&) {
		std::fprintf(stderr, "[Zone][vmdisp] response conversion failed\n");
		return 0;
	}
}

// 供 cloud_value_manager 取回当前 V（32 字节原始值）。成功返回 1。
extern "C" int xollvm_zone_vm_dispatch_copy_v(uint8_t* out32) {
	if (!out32)
		return 0;
	ZoneState& s = state();
	std::lock_guard<std::mutex> lock(s.mutex);
	if (s.dispatchV.size() != 32)
		return 0;
	std::memcpy(out32, s.dispatchV.data(), 32);
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

extern "C" char* xollvm_zone_vm_body_key(const char* function_id) {
	ZoneState& s = state();
	std::lock_guard<std::mutex> lock(s.mutex);
	if (s.algorithm != "capability_v1" || s.dispatchSignedBlob.empty() ||
		!function_id || function_id[0] == '\0')
		return nullptr;
	const char* deviceId = std::getenv("XOLLVM_ZONE_DEVICE_ID");
	if (!deviceId || !deviceId[0])
		return nullptr;
	const uint64_t tick = xollvm::readClientTick();
	static thread_local std::string key;
	key = xollvm::unwrapBodyKey(s.dispatchSignedBlob, deviceId, tick,
		s.dispatchNonce, function_id);
	if (key.empty())
		return nullptr;
	return const_cast<char*>(key.c_str());
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
