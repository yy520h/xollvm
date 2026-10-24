#include "runtime/cloud_material/material_store.h"

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <stdexcept>
#include <thread>
#include <vector>
#include <sys/wait.h>
#include <unistd.h>

using nlohmann::json;
using namespace xovm::material;

namespace {
std::atomic<bool> gBytecodeCleared{false};
std::atomic<bool> gMapCleared{false};

void observeZeroize(bool bytecodeCleared, bool mapCleared) {
    gBytecodeCleared.store(bytecodeCleared, std::memory_order_release);
    gMapCleared.store(mapCleared, std::memory_order_release);
}

std::vector<uint8_t> base64(const std::string &encoded) {
    static constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> result;
    uint32_t bits = 0;
    unsigned count = 0;
    for (char character : encoded) {
        if (character == '=') break;
        const auto position = alphabet.find(character);
        if (position == std::string_view::npos) throw std::runtime_error("fixture_base64");
        bits = (bits << 6) | static_cast<uint32_t>(position);
        count += 6;
        if (count >= 8) {
            count -= 8;
            result.push_back(static_cast<uint8_t>(bits >> count));
        }
    }
    return result;
}

std::array<uint8_t, 32> hex32(const std::string &encoded) {
    if (encoded.size() != 64) throw std::runtime_error("fixture_hex");
    std::array<uint8_t, 32> result{};
    auto digit = [](char value) -> uint8_t {
        if (value >= '0' && value <= '9') return static_cast<uint8_t>(value - '0');
        if (value >= 'a' && value <= 'f') return static_cast<uint8_t>(value - 'a' + 10);
        throw std::runtime_error("fixture_hex");
    };
    for (size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<uint8_t>((digit(encoded[index * 2]) << 4) |
                                             digit(encoded[index * 2 + 1]));
    return result;
}

struct AuthFixture {
    VerifiedPackage package;
    RequestTiming timing;
    uint64_t original_sent_ns;
    explicit AuthFixture(VerifiedPackage value, RequestTiming requestTiming)
        : package(std::move(value)), timing(requestTiming),
          original_sent_ns(requestTiming.sent_boot_ns) {}
};

AuthFixture authenticate(const json &fixture) {
    const auto installed = fixture.at("installed");
    InstalledTrust trust{
        installed.at("software_id").get<std::string>(),
        installed.at("root_key_id").get<std::string>(),
        hex32(fixture.at("root_public_key").get<std::string>()),
        1000001, 1000002,
    };
    const auto trustBytes = base64(fixture.at("trust_bundle").get<std::string>());
    auto verifiedTrust = verifyTrustBundle(trustBytes, trust);
    if (auto *error = std::get_if<ProtocolError>(&verifiedTrust))
        throw std::runtime_error(error->code);
    const auto expectedValue = fixture.at("expected");
    ExpectedMaterial expected{
        expectedValue.at("software_id").get<std::string>(),
        expectedValue.at("build_id").get<std::string>(),
        expectedValue.at("final_artifact_hash").get<std::string>(),
        expectedValue.at("session_id").get<std::string>(),
        expectedValue.at("counter_epoch").get<std::string>(),
        expectedValue.at("region_id").get<std::string>(),
        expectedValue.at("engine_abi_hash").get<std::string>(),
        expectedValue.at("mode").get<std::string>(),
    };
    const auto requestBytes = base64(fixture.at("request").get<std::string>());
    PendingRequest pending(requestBytes,
        hex32(fixture.at("client_private_key").get<std::string>()),
        std::get<VerifiedTrustBundle>(std::move(verifiedTrust)), std::move(expected),
        std::stoull(fixture.at("sent_boot_ns").get<std::string>()),
        std::stoull(fixture.at("received_boot_ns").get<std::string>()));
    const auto responseBytes = base64(fixture.at("response").get<std::string>());
    auto authenticated = authenticateResponse(responseBytes, pending);
    if (auto *error = std::get_if<ProtocolError>(&authenticated))
        throw std::runtime_error(error->code);
    return AuthFixture(std::get<VerifiedPackage>(std::move(authenticated)),
        {std::stoull(fixture.at("sent_boot_ns").get<std::string>()),
         std::stoull(fixture.at("received_boot_ns").get<std::string>())});
}

void emit(json value) {
    value["ok"] = true;
    std::cout << value.dump() << '\n';
}
} // namespace

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const std::string test = argv[1];
    std::string ignored;
    std::getline(std::cin, ignored);
    const std::string input(std::istreambuf_iterator<char>(std::cin), {});
    try {
        const auto inputValue = json::parse(input);
        const bool pair = test == "publish_while_pinned" ||
            test == "publish_session_mismatch" || test == "publish_generation_rollback";
        auto first = authenticate(pair ? inputValue.at("first") : inputValue);
        if (test == "pin_at_119_expire_at_120") {
            MaterialStore store;
            setMaterialZeroizeObserverForTest(observeZeroize);
            if (store.publish(std::move(first.package), first.timing) != StoreError::None)
                throw std::runtime_error("publish_failed");
            const auto region = inputValue.at("expected").at("region_id").get<std::string>();
            auto pin = store.acquire(region, first.original_sent_ns + 119000000000ULL);
            const bool live = pin.material && pin.material.package()->bytecode[0] == 1;
            const auto atDeadline = store.acquire(region, first.original_sent_ns + 120000000000ULL);
            const bool newAcquired = static_cast<bool>(atDeadline.material);
            pin.material.release();
            const bool cleared = gBytecodeCleared.load(std::memory_order_acquire) &&
                gMapCleared.load(std::memory_order_acquire);
            emit({{"old_call_completed", live}, {"new_call_acquired", newAcquired},
                  {"old_bytes_live_until_release", live}, {"old_bytes_cleared_after_release", cleared}});
        } else if (test == "same_request_late_retry") {
            const auto deadline = first.original_sent_ns + 120000000000ULL;
            MaterialStore store;
            const auto result = store.publish(std::move(first.package),
                {first.original_sent_ns, deadline});
            emit({{"deadline_ns", deadline}, {"original_sent_ns", first.original_sent_ns},
                  {"accepted_after_deadline", result == StoreError::None}});
        } else if (test == "timing_mismatch") {
            MaterialStore store;
            const auto result = store.publish(std::move(first.package),
                {first.original_sent_ns + 1, first.timing.received_boot_ns + 1});
            emit({{"accepted_after_deadline", result == StoreError::None}});
        } else if (test == "short_lease" || test == "ten_second_lease") {
            MaterialStore store;
            if (store.publish(std::move(first.package), first.timing) != StoreError::None)
                throw std::runtime_error("publish_failed");
            auto pin = store.acquire(inputValue.at("expected").at("region_id").get<std::string>(),
                                     first.original_sent_ns);
            if (!pin.material) throw std::runtime_error("acquire_failed");
            emit({{"deadline_ns", pin.material.deadlineNs()},
                  {"renew_at_ns", pin.material.renewAtNs()}, {"sent_ns", first.original_sent_ns},
                  {"ten_second_lease_renews_immediately", pin.material.renewAtNs() == first.original_sent_ns}});
        } else if (test == "session_material") {
            MaterialStore store;
            if (store.publish(std::move(first.package), first.timing) != StoreError::None)
                throw std::runtime_error("publish_failed");
            const auto region = inputValue.at("expected").at("region_id").get<std::string>();
            auto pin = store.acquire(region, first.original_sent_ns + 3600000000000ULL);
            emit({{"acquired_after_lease_horizon", static_cast<bool>(pin.material)},
                  {"has_deadline", pin.material.hasDeadline()}});
        } else if (test == "publish_while_pinned") {
            auto second = authenticate(inputValue.at("second"));
            MaterialStore store;
            setMaterialZeroizeObserverForTest(observeZeroize);
            if (store.publish(std::move(first.package), first.timing) != StoreError::None)
                throw std::runtime_error("publish_first_failed");
            const auto region = inputValue.at("first").at("expected").at("region_id").get<std::string>();
            auto oldPin = store.acquire(region, first.original_sent_ns + 1000);
            if (!oldPin.material || oldPin.material.package()->binding.generation != 1)
                throw std::runtime_error("old_pin_failed");
            std::atomic<bool> pinned{false};
            std::atomic<bool> finish{false};
            bool oldStayed = false;
            std::thread worker([&] {
                pinned.store(true, std::memory_order_release);
                while (!finish.load(std::memory_order_acquire)) std::this_thread::yield();
                oldStayed = oldPin.material.package()->binding.generation == 1;
                oldPin.material.release();
            });
            while (!pinned.load(std::memory_order_acquire)) std::this_thread::yield();
            if (store.publish(std::move(second.package), second.timing) != StoreError::None) {
                finish.store(true, std::memory_order_release);
                worker.join();
                throw std::runtime_error("publish_second_failed");
            }
            auto newPin = store.acquire(region, second.original_sent_ns + 1000);
            if (!newPin.material) {
                finish.store(true, std::memory_order_release);
                worker.join();
                throw std::runtime_error("new_pin_failed");
            }
            const auto newGeneration = newPin.material.package()->binding.generation;
            finish.store(true, std::memory_order_release);
            worker.join();
            const bool cleared = gBytecodeCleared.load(std::memory_order_acquire) &&
                gMapCleared.load(std::memory_order_acquire);
            emit({{"old_generation", "1"}, {"new_generation", std::to_string(newGeneration)},
                  {"old_call_stayed_generation_one", oldStayed},
                  {"old_bytes_cleared_after_release", cleared}});
        } else if (test == "publish_session_mismatch" ||
                   test == "publish_generation_rollback") {
            MaterialStore store;
            if (store.publish(std::move(first.package), first.timing) != StoreError::None)
                throw std::runtime_error("publish_first_failed");
            auto second = authenticate(inputValue.at("second"));
            const auto rejected = store.publish(std::move(second.package), second.timing);
            auto current = store.acquire(
                inputValue.at("first").at("expected").at("region_id").get<std::string>(),
                first.original_sent_ns + 1000);
            if (!current.material) throw std::runtime_error("current_generation_lost");
            emit({{"replacement_accepted", rejected == StoreError::None},
                  {"current_generation", std::to_string(current.material.package()->binding.generation)}});
        } else if (test == "recursive_expired") {
            MaterialStore store;
            if (store.publish(std::move(first.package), first.timing) != StoreError::None)
                throw std::runtime_error("publish_failed");
            auto outer = store.acquire(inputValue.at("expected").at("region_id").get<std::string>(),
                                       first.original_sent_ns + 119000000000ULL);
            const bool outerLive = static_cast<bool>(outer.material);
            auto recursive = store.acquire(inputValue.at("expected").at("region_id").get<std::string>(),
                                           first.original_sent_ns + 120000000000ULL);
            emit({{"outer_call_completed", outerLive},
                  {"recursive_acquired", static_cast<bool>(recursive.material)}});
        } else if (test == "shutdown") {
            MaterialStore store;
            setMaterialZeroizeObserverForTest(observeZeroize);
            if (store.publish(std::move(first.package), first.timing) != StoreError::None)
                throw std::runtime_error("publish_failed");
            const auto region = inputValue.at("expected").at("region_id").get<std::string>();
            auto pin = store.acquire(region, first.original_sent_ns);
            const auto idle = store.acquire(region, first.original_sent_ns + 120000000000ULL);
            store.shutdown();
            auto blocked = store.acquire(region, first.original_sent_ns);
            const bool live = pin.material && pin.material.package()->bytecode[0] == 1;
            pin.material.release();
            emit({{"idle_expiry_faulted", idle.error != StoreError::Expired},
                  {"pinned_call_completed", live},
                  {"new_call_acquired", static_cast<bool>(blocked.material)},
                  {"bytes_cleared_after_release", gBytecodeCleared.load(std::memory_order_acquire) &&
                      gMapCleared.load(std::memory_order_acquire)}});
        } else if (test == "fork_rejected") {
            MaterialStore store;
            if (store.publish(std::move(first.package), first.timing) != StoreError::None)
                throw std::runtime_error("publish_failed");
            const auto region = inputValue.at("expected").at("region_id").get<std::string>();
            auto parentPin = store.acquire(region, first.original_sent_ns);
            if (!parentPin.material) throw std::runtime_error("parent_pin_failed");
            pid_t child = fork();
            if (child < 0) throw std::runtime_error("fork_failed");
            if (child == 0) {
                const bool rejected = store.acquire(region, first.original_sent_ns).error ==
                    StoreError::ForkedProcess && parentPin.material.package() == nullptr;
                _exit(rejected ? 0 : 1);
            }
            int status = 0;
            if (waitpid(child, &status, 0) != child) throw std::runtime_error("waitpid_failed");
            emit({{"child_rejected", WIFEXITED(status) && WEXITSTATUS(status) == 0},
                  {"child_exit_status", WIFEXITED(status) ? WEXITSTATUS(status) : 255},
                  {"parent_still_acquired", static_cast<bool>(parentPin.material)}});
        } else {
            throw std::runtime_error("unknown_case");
        }
        return 0;
    } catch (const std::exception &error) {
        if (test == "late_response" && std::string_view(error.what()) == "expired_response") {
            emit({{"accepted", false}, {"code", "expired_response"}});
            return 0;
        }
        std::cerr << "fixture_failure:" << error.what() << '\n';
        return 3;
    }
}
