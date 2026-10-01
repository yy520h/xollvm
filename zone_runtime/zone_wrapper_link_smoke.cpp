#include "zone_wrapper.h"

int main() {
	if (xollvm_zone_initialize("", "", "", "", "", 120, 180) != 0)
		return 1;
	xollvm_zone_shutdown();
	return xollvm_zone_require("main") == 0 ? 0 : 1;
}
