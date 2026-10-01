#ifndef __HW_INFO_H__
#define __HW_INFO_H__
#include <string>

bool hw_init();
bool hw_cleanup();

bool get_board_serial_number(std::string& board_serial);
bool get_cpu_id(std::string& cpu_id);
bool get_disk_id(std::string& serial);
bool get_mac_address(std::string& mac_address);
bool get_machine_guid(std::string& out);
std::string get_persistent_device_id();
bool get_bios_serial(std::string& out);
bool get_os_disk_serial(std::string& serial);
std::string hw_normalize_token(const std::string& raw);

#endif
