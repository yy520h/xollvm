#include "config.h"
#include "process_lock.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <string>
#include <utility>
#include <sys/wait.h>
#include <unistd.h>

namespace {
using namespace xovm::cloud_material;

struct TestState {
    unsigned assertions = 0;
    unsigned failures = 0;
    const char *test_name = "";
};

TestState state;

bool expect(bool condition, const char *expression, int line) {
    ++state.assertions;
    if (condition) return true;
    ++state.failures;
    std::fprintf(stderr, "line %d: %s failed in %s\n", line, expression, state.test_name);
    return false;
}

#define EXPECT_TRUE(expression) expect(static_cast<bool>(expression), #expression, __LINE__)
#define EXPECT_FALSE(expression) expect(!static_cast<bool>(expression), "! (" #expression ")", __LINE__)
#define TEST(name) static void name()

std::map<std::string, std::string> completeEnvironment() {
    return {
        {"XOVM_SQLITE_PATH", "/tmp/xovm-cloud-material.sqlite"},
        {"XOVM_STATE_DIR", "/tmp/xovm-cloud-material-state"},
        {"XOVM_RELAY_TOKEN", std::string(32, 'r')},
        {"XOVM_ADMIN_TOKEN", std::string(32, 'a')},
        {"XOVM_TRUSTED_TIME_PROVIDER", "trusted-time"},
        {"XOVM_SIGNING_KEY_PROVIDER", "signing-key"},
        {"XOVM_ANONYMOUS_POLICY_PROVIDER", "anonymous-policy"},
        {"XOVM_TRUST_ROOT_PROVIDER", "trust-root"},
    };
}

BackendConfigResult parse(std::map<std::string, std::string> values) {
    return BackendConfig::fromEnvironment([values = std::move(values)](std::string_view name) {
        const auto found = values.find(std::string(name));
        return found == values.end() ? std::string{} : found->second;
    });
}

std::filesystem::path lockDirectory(const char *name) {
    return std::filesystem::temp_directory_path() /
        (std::string("xovm-cloud-material-") + name + "-" + std::to_string(::getpid()));
}

TEST(config_rejects_missing_required_value) {
    auto values = completeEnvironment();
    values.erase("XOVM_RELAY_TOKEN");
    auto result = parse(std::move(values));
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    if (std::holds_alternative<BackendError>(result))
        EXPECT_TRUE(std::get<BackendError>(result).code == "config_missing_XOVM_RELAY_TOKEN");
}

TEST(config_rejects_short_or_reused_credentials) {
    auto values = completeEnvironment();
    values["XOVM_RELAY_TOKEN"] = "short";
    auto shortResult = parse(values);
    EXPECT_TRUE(std::holds_alternative<BackendError>(shortResult));
    values["XOVM_RELAY_TOKEN"] = values["XOVM_ADMIN_TOKEN"];
    auto reusedResult = parse(std::move(values));
    EXPECT_TRUE(std::holds_alternative<BackendError>(reusedResult));
    if (std::holds_alternative<BackendError>(reusedResult))
        EXPECT_TRUE(std::get<BackendError>(reusedResult).code == "config_credentials_must_differ");
}

TEST(config_rejects_unsafe_bind_and_bounds) {
    auto values = completeEnvironment();
    values["XOVM_BIND_ADDRESS"] = "0.0.0.0";
    auto unsafeBind = parse(values);
    EXPECT_TRUE(std::holds_alternative<BackendError>(unsafeBind));
    values["XOVM_BIND_ADDRESS"] = "127.0.0.1";
    values["PORT"] = "0";
    auto badPort = parse(values);
    EXPECT_TRUE(std::holds_alternative<BackendError>(badPort));
    values["PORT"] = "8080";
    values["XOVM_RAW_PORT"] = "18080";
    values["REQUEST_TIMEOUT_MS"] = "99";
    auto badTimeout = parse(values);
    EXPECT_TRUE(std::holds_alternative<BackendError>(badTimeout));
    values["REQUEST_TIMEOUT_MS"] = "10000";
    values["MAX_CONCURRENT_REQUESTS"] = "0";
    auto badConcurrency = parse(std::move(values));
    EXPECT_TRUE(std::holds_alternative<BackendError>(badConcurrency));
}

TEST(config_accepts_loopback_defaults) {
    auto result = parse(completeEnvironment());
    EXPECT_TRUE(std::holds_alternative<BackendConfig>(result));
    if (std::holds_alternative<BackendConfig>(result)) {
        const auto &config = std::get<BackendConfig>(result);
        EXPECT_TRUE(config.bind_address == "127.0.0.1");
        EXPECT_TRUE(config.port == 8080);
        EXPECT_TRUE(config.raw_port == 0);
        EXPECT_TRUE(config.request_timeout_ms == 10000);
        EXPECT_TRUE(config.max_concurrent_requests == 128);
    }
}

TEST(config_reads_process_environment) {
    const auto values = completeEnvironment();
    for (const auto &[name, value] : values) ::setenv(name.c_str(), value.c_str(), 1);
    ::unsetenv("XOVM_BIND_ADDRESS");
    ::unsetenv("PORT");
    ::unsetenv("REQUEST_TIMEOUT_MS");
    ::unsetenv("MAX_CONCURRENT_REQUESTS");
    auto result = BackendConfig::fromEnvironment();
    EXPECT_TRUE(std::holds_alternative<BackendConfig>(result));
    for (const auto &[name, value] : values) ::unsetenv(name.c_str());
}

TEST(process_lock_rejects_second_owner_and_releases) {
    const auto directory = lockDirectory("owner");
    std::filesystem::remove_all(directory);
    {
        auto first = ProcessLock::acquire(directory);
        EXPECT_TRUE(std::holds_alternative<ProcessLock>(first));
        auto second = ProcessLock::acquire(directory);
        EXPECT_TRUE(std::holds_alternative<BackendError>(second));
    }
    auto afterRelease = ProcessLock::acquire(directory);
    EXPECT_TRUE(std::holds_alternative<ProcessLock>(afterRelease));
    std::filesystem::remove_all(directory);
}

TEST(process_lock_rejects_forked_child_owner) {
    const auto directory = lockDirectory("fork");
    std::filesystem::remove_all(directory);
    auto owner = ProcessLock::acquire(directory);
    EXPECT_TRUE(std::holds_alternative<ProcessLock>(owner));
    if (std::holds_alternative<ProcessLock>(owner)) {
        const auto child = ::fork();
        EXPECT_TRUE(child >= 0);
        if (child == 0) {
            auto competing = ProcessLock::acquire(directory);
            _exit(std::holds_alternative<BackendError>(competing) ? 0 : 1);
        }
        int status = 0;
        EXPECT_TRUE(::waitpid(child, &status, 0) == child);
        EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    std::filesystem::remove_all(directory);
}

TEST(process_lock_recovers_stale_lock_file) {
    const auto directory = lockDirectory("stale");
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);
    const auto lockPath = directory / ".xovm.lock";
    std::FILE *file = std::fopen(lockPath.c_str(), "w");
    EXPECT_TRUE(file != nullptr);
    if (file != nullptr) {
        std::fputs("stale pid", file);
        std::fclose(file);
    }
    auto lock = ProcessLock::acquire(directory);
    EXPECT_TRUE(std::holds_alternative<ProcessLock>(lock));
    std::filesystem::remove_all(directory);
}

TEST(process_lock_rejects_state_path_that_is_a_file) {
    const auto directory = lockDirectory("not-directory");
    std::filesystem::remove_all(directory);
    std::FILE *file = std::fopen(directory.c_str(), "w");
    EXPECT_TRUE(file != nullptr);
    if (file != nullptr) std::fclose(file);
    auto lock = ProcessLock::acquire(directory);
    EXPECT_TRUE(std::holds_alternative<BackendError>(lock));
    std::filesystem::remove(directory);
}

template <typename Test>
void run(const char *name, Test test) {
    const unsigned before = state.failures;
    state.test_name = name;
    test();
    std::fprintf(state.failures == before ? stdout : stderr, "[%s] %s\n",
                 state.failures == before ? "PASS" : "FAIL", name);
}
} // namespace

int main() {
    run("config_rejects_missing_required_value", config_rejects_missing_required_value);
    run("config_rejects_short_or_reused_credentials", config_rejects_short_or_reused_credentials);
    run("config_rejects_unsafe_bind_and_bounds", config_rejects_unsafe_bind_and_bounds);
    run("config_accepts_loopback_defaults", config_accepts_loopback_defaults);
    run("config_reads_process_environment", config_reads_process_environment);
    run("process_lock_rejects_second_owner_and_releases",
        process_lock_rejects_second_owner_and_releases);
    run("process_lock_rejects_forked_child_owner", process_lock_rejects_forked_child_owner);
    run("process_lock_recovers_stale_lock_file", process_lock_recovers_stale_lock_file);
    run("process_lock_rejects_state_path_that_is_a_file",
        process_lock_rejects_state_path_that_is_a_file);
    std::fprintf(stdout, "9 tests, %u assertions, %u failures\n",
                 state.assertions, state.failures);
    return state.failures == 0 ? 0 : 1;
}
