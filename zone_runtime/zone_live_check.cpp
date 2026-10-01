#include "zone_wrapper.h"

#include <cstdlib>
#include <iostream>
#include <string>

static const char* envOrEmpty(const char* name) {
	const char* value = std::getenv(name);
	return value ? value : "";
}

int main() {
	if (std::string(envOrEmpty("XOLLVM_ZONE_LIVE")) != "1") {
		std::cerr << "Set XOLLVM_ZONE_LIVE=1 to enable a real Zone request.\n";
		return 2;
	}

	const char* card = envOrEmpty("XOLLVM_ZONE_CARD");
	if (*card == '\0') {
		std::cerr << "XOLLVM_ZONE_CARD is required.\n";
		return 2;
	}

	if (!xollvm_zone_initialize(
		envOrEmpty("XOLLVM_ZONE_SOFTWARE_ID"),
		envOrEmpty("XOLLVM_ZONE_VERSION"),
		envOrEmpty("XOLLVM_ZONE_ENCRYPT_KEY"),
		envOrEmpty("XOLLVM_ZONE_ENCRYPT_IV"),
		envOrEmpty("XOLLVM_ZONE_ALGORITHM"), 120, 180)) {
		std::cerr << "Zone initialize failed.\n";
		return 1;
	}

	if (!xollvm_zone_login_card(card)) {
		std::cerr << "Zone card login failed.\n";
		xollvm_zone_shutdown();
		return 1;
	}
	std::cout << "Zone card login succeeded.\n";

	if (!xollvm_zone_first_heartbeat()) {
		std::cerr << "Zone first heartbeat/cloud algorithm failed.\n";
		xollvm_zone_shutdown();
		return 1;
	}
	std::cout << "Zone first heartbeat and cloud algorithm succeeded.\n";

	int allowed = xollvm_zone_require("main");
	std::cout << "Capability main: " << (allowed ? "allowed" : "denied") << '\n';
	xollvm_zone_shutdown();
	return allowed ? 0 : 1;
}
