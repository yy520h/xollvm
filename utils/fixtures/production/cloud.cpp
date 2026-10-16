// 复用实际 demo 的保护函数和本地配置，构建时传入源码路径。
#define main original_demo_main
#include XOLLVM_DEMO_SOURCE
#undef main

#include "cloud_value_manager.h"
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <initializer_list>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

static std::atomic<bool> blocked{false};
static std::atomic<unsigned> denied{0};
static int faultFd = -1;
static volatile sig_atomic_t armed = 0;
static uint64_t mainTid = 0;
// 固定长度二进制现场：handler 只做内存读取、write 和返回，不调用日志/分配器。
static uint64_t evidence[332]{};
extern "C" uint64_t __real___zone_get_dispatch_offset();
extern "C" uint64_t __wrap___zone_get_dispatch_offset();
extern "C" void acceptance_capture(const uint64_t* registers, uint64_t sp) {
	if (!armed || uint64_t(syscall(SYS_gettid)) != mainTid) return;
	evidence[8] = registers[30];
	evidence[9] = sp;
	for (unsigned i = 0; i < 31; ++i) evidence[10 + i] = registers[i];
	for (unsigned i = 0; i < 256; ++i)
		evidence[41 + i] = reinterpret_cast<const volatile uint64_t*>(sp)[i];
	++evidence[7];
}

// 捕获真正 offset 调用返回后的寄存器；恢复后不改变 VM 看到的 ABI 状态。
asm(R"(
.text
.global __wrap___zone_get_dispatch_offset
.type __wrap___zone_get_dispatch_offset,%function
__wrap___zone_get_dispatch_offset:
 sub sp, sp, #256
 str x30, [sp, #240]
 bl __real___zone_get_dispatch_offset
 stp x0, x1, [sp, #0]
 stp x2, x3, [sp, #16]
 stp x4, x5, [sp, #32]
 stp x6, x7, [sp, #48]
 stp x8, x9, [sp, #64]
 stp x10, x11, [sp, #80]
 stp x12, x13, [sp, #96]
 stp x14, x15, [sp, #112]
 stp x16, x17, [sp, #128]
 stp x18, x19, [sp, #144]
 stp x20, x21, [sp, #160]
 stp x22, x23, [sp, #176]
 stp x24, x25, [sp, #192]
 stp x26, x27, [sp, #208]
 stp x28, x29, [sp, #224]
 mov x0, sp
 add x1, sp, #256
 bl acceptance_capture
 ldp x0, x1, [sp, #0]
 ldp x2, x3, [sp, #16]
 ldp x4, x5, [sp, #32]
 ldp x6, x7, [sp, #48]
 ldp x8, x9, [sp, #64]
 ldp x10, x11, [sp, #80]
 ldp x12, x13, [sp, #96]
 ldp x14, x15, [sp, #112]
 ldp x16, x17, [sp, #128]
 ldp x18, x19, [sp, #144]
 ldp x20, x21, [sp, #160]
 ldp x22, x23, [sp, #176]
 ldp x24, x25, [sp, #192]
 ldp x26, x27, [sp, #208]
 ldp x28, x29, [sp, #224]
 ldr x30, [sp, #240]
 add sp, sp, #256
 ret
.size __wrap___zone_get_dispatch_offset, .-__wrap___zone_get_dispatch_offset
)");

static void captureFault(int sig, siginfo_t* info, void* context) {
	auto* state = static_cast<ucontext_t*>(context);
	evidence[0] = 0x584f4641554c5431ULL;
	evidence[1] = sig;
	evidence[2] = info->si_code;
	evidence[3] = uint64_t(syscall(SYS_gettid));
	evidence[4] = state->uc_mcontext.pc;
	evidence[5] = reinterpret_cast<uint64_t>(info->si_addr);
	for (unsigned i = 0; i < 31; ++i) evidence[300 + i] = state->uc_mcontext.regs[i];
	evidence[331] = state->uc_mcontext.sp;
	if (faultFd >= 0) {
		const char* data = reinterpret_cast<const char*>(evidence);
		size_t remaining = sizeof(evidence);
		while (remaining) {
			ssize_t count = write(faultFd, data, remaining);
			if (count <= 0) break;
			data += count;
			remaining -= count;
		}
	}
	// SA_RESETHAND 已恢复默认动作，返回后原故障指令再次触发同一信号。
}

static bool setupFaultCapture(const char* path) {
	faultFd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (faultFd < 0) return false;
	Dl_info image{};
	if (!dladdr(reinterpret_cast<void*>(&setupFaultCapture), &image)) return false;
	evidence[6] = reinterpret_cast<uint64_t>(image.dli_fbase);
	mainTid = uint64_t(syscall(SYS_gettid));
	evidence[297] = mainTid;
	struct sigaction action{};
	action.sa_sigaction = captureFault;
	action.sa_flags = SA_SIGINFO | SA_RESETHAND;
	sigemptyset(&action.sa_mask);
	for (int sig : {SIGTRAP, SIGILL, SIGSEGV, SIGABRT})
		if (sigaction(sig, &action, nullptr)) return false;
	return true;
}
extern "C" int __real_connect(int, const sockaddr*, socklen_t);
extern "C" int __wrap_connect(int fd, const sockaddr* address, socklen_t size) {
	if (blocked.load() && address &&
		(address->sa_family == AF_INET || address->sa_family == AF_INET6)) {
		++denied;
		errno = ENETUNREACH;
		return -1;
	}
	return __real_connect(fd, address, size);
}

static unsigned disconnectSockets() {
	blocked.store(true);
	DIR* directory = opendir("/proc/self/fd");
	if (!directory) return 0;
	unsigned count = 0;
	while (auto* entry = readdir(directory)) {
		char* end;
		long fd = strtol(entry->d_name, &end, 10);
		if (*end || fd < 0) continue;
		sockaddr_storage address{};
		socklen_t length = sizeof(address);
		if (getsockname(int(fd), reinterpret_cast<sockaddr*>(&address), &length) == 0 &&
			(address.ss_family == AF_INET || address.ss_family == AF_INET6)) {
			// 不 close，避免其他线程复用 fd 后被误关。
			shutdown(int(fd), SHUT_RDWR);
			++count;
		}
	}
	closedir(directory);
	return count;
}

static bool check(unsigned iteration) {
	int result = runProtectedDemo(703);
	std::printf("call=%u window=%llu value=%d\n", iteration,
		static_cast<unsigned long long>(xollvm::CloudValueManager::getInstance().getWindowId()), result);
	std::fflush(stdout);
	return result == 11299;
}

int main(int argc, char** argv) {
	if (argc != 2 && argc != 3) return 2;
	const std::string mode = argv[1];
	if (mode == "unrelated-trap" || mode == "offset-unrelated-trap" || mode == "background-trap") {
		if (argc != 3 || !setupFaultCapture(argv[2])) return 2;
		armed = 1;
		if (mode == "offset-unrelated-trap") __wrap___zone_get_dispatch_offset();
		if (mode == "background-trap") {
			std::thread([] { __builtin_trap(); }).join();
		}
		__builtin_trap();
	}
	if (mode != "online" && mode != "offline-expiry" && mode != "recovery") return 2;
	if (mode == "offline-expiry" && (argc != 3 || !setupFaultCapture(argv[2]))) return 2;
	const char* card = std::getenv("XOLLVM_ZONE_CARD");
	if (!card || !*card) return 2;
	if (!xollvm_zone_initialize(ZoneSoftwareId, ZoneVersion, ZoneEncryptKey,
		ZoneEncryptIv, "capability_v1", "key-1", 120, 180)) return 3;
	xollvm_zone_set_shutdown_mode(1);
	if (!xollvm_zone_login_card(card) || !xollvm_zone_first_heartbeat() ||
		!xollvm_zone_capability_begin("demo_sensitive_action", "") ||
		!xollvm_zone_require("demo_sensitive_action")) return 4;
	if (!check(0)) return 5;
	auto& manager = xollvm::CloudValueManager::getInstance();
	const uint64_t first = manager.getWindowId();
	if (mode == "online") {
		for (unsigned i = 1; i <= 125; ++i) {
			std::this_thread::sleep_for(std::chrono::seconds(1));
			if (!check(i)) return 6;
		}
		if (manager.getWindowId() < first + 2) return 7;
	} else {
		std::printf("offline start closed=%u window=%llu\n", disconnectSockets(),
			static_cast<unsigned long long>(first));
		std::fflush(stdout);
		while (manager.getWindowId() == first)
			std::this_thread::sleep_for(std::chrono::milliseconds(200));
		std::this_thread::sleep_for(std::chrono::seconds(2));
		uint64_t offset = manager.computeDispatchOffset();
		int refresh = xollvm_zone_vm_dispatch_refresh();
		std::printf("offline expired window=%llu offset=%llu refresh=%d denied=%u\n",
			static_cast<unsigned long long>(manager.getWindowId()),
			static_cast<unsigned long long>(offset), refresh, denied.load());
		std::fflush(stdout);
		if (!offset || refresh || !denied.load()) return 8;
		if (mode == "offline-expiry") {
			std::puts("calling expired VM; abnormal termination expected");
			std::fflush(stdout);
			armed = 1;
			check(1);
			return 9;
		}
		blocked.store(false);
		if (!check(1) || manager.computeDispatchOffset() != 0) return 10;
		std::puts("network restored offset=0");
	}
	xollvm_zone_shutdown();
	std::puts("acceptance complete");
	return 0;
}
