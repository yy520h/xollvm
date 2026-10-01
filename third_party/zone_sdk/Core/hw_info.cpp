#include "hw_info.h"
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <unistd.h>

std::string hw_normalize_token(const std::string& raw);

static std::string read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::stringstream ss;
    ss << f.rdbuf();
    std::string s = ss.str();
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

static std::string get_prop(const char* name) {
    char buf[PROP_VALUE_MAX] = {0};
    if (__system_property_get(name, buf) > 0) {
        return std::string(buf);
    }
    return "";
}

static std::string configured_device_id_path() {
    const char* configured = std::getenv("XOLLVM_ZONE_DEVICE_ID_PATH");
    if (configured && *configured)
        return configured;
    return "/data/data/com.termux/files/home/.config/xollvm/zone-device-id";
}

static bool ensure_parent_directory(const std::string& path) {
    const size_t slash = path.find_last_of('/');
    if (slash == std::string::npos)
        return true;
    const std::string parent = path.substr(0, slash);
    for (size_t pos = 1; pos <= parent.size(); ++pos) {
        if (pos != parent.size() && parent[pos] != '/')
            continue;
        const std::string dir = parent.substr(0, pos);
        if (!dir.empty() && mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST)
            return false;
    }
    return true;
}

static std::string make_persistent_device_id(const std::string& path) {
    if (!ensure_parent_directory(path))
        return "";

    const int lockFd = open((path + ".lock").c_str(), O_CREAT | O_RDWR, 0600);
    if (lockFd < 0)
        return "";
    if (flock(lockFd, LOCK_EX) != 0) {
        close(lockFd);
        return "";
    }

    std::ifstream existing(path);
    std::string value;
    if (existing && std::getline(existing, value)) {
        value = hw_normalize_token(value);
        if (!value.empty()) {
            flock(lockFd, LOCK_UN);
            close(lockFd);
            return value;
        }
    }

    try {
        std::random_device rd;
        std::ostringstream generated;
        generated << "xollvm-" << std::hex << std::setfill('0');
        for (int i = 0; i < 16; ++i)
            generated << std::setw(2) << (rd() & 0xff);
        value = generated.str();
    }
    catch (...) {
        value = "xollvm-persistent-device";
    }

    const std::string temporary = path + ".tmp." + std::to_string(getpid());
    std::ofstream output(temporary, std::ios::trunc);
    bool persisted = false;
    if (output) {
        output << value << '\n';
        output.close();
        persisted = rename(temporary.c_str(), path.c_str()) == 0;
        if (persisted)
            chmod(path.c_str(), 0600);
    }
    if (!persisted)
        remove(temporary.c_str());
    flock(lockFd, LOCK_UN);
    close(lockFd);
    return persisted ? value : "";
}

std::string get_persistent_device_id() {
    const std::string configured = configured_device_id_path();
    std::string value = make_persistent_device_id(configured);
    if (!value.empty())
        return value;

    const char* home = std::getenv("HOME");
    if (home && *home) {
        value = make_persistent_device_id(
            std::string(home) + "/.config/xollvm/zone-device-id");
        if (!value.empty())
            return value;
    }
    return "";
}

bool hw_init() {
    return true;
}

bool hw_cleanup() {
    return true;
}

bool get_board_serial_number(std::string& board_serial) {
    board_serial = get_prop("ro.boot.serialno");
    if (board_serial.empty()) {
        board_serial = get_prop("ro.serialno");
    }
    return !board_serial.empty();
}

bool get_cpu_id(std::string& cpu_id) {
    std::ifstream f("/proc/cpuinfo");
    if (!f.is_open()) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.find("Serial") != std::string::npos) {
            size_t pos = line.find(':');
            if (pos != std::string::npos) {
                cpu_id = line.substr(pos + 1);
                size_t start = cpu_id.find_first_not_of(" \t");
                if (start != std::string::npos) cpu_id = cpu_id.substr(start);
                return !cpu_id.empty();
            }
        }
    }
    f.clear();
    f.seekg(0);
    while (std::getline(f, line)) {
        if (line.find("Hardware") != std::string::npos) {
            size_t pos = line.find(':');
            if (pos != std::string::npos) {
                cpu_id = line.substr(pos + 1);
                size_t start = cpu_id.find_first_not_of(" \t");
                if (start != std::string::npos) cpu_id = cpu_id.substr(start);
                return !cpu_id.empty();
            }
        }
    }
    return false;
}

bool get_disk_id(std::string& serial) {
    return get_os_disk_serial(serial);
}

bool get_mac_address(std::string& mac_address) {
    const char* paths[] = {
        "/sys/class/net/wlan0/address",
        "/sys/class/net/eth0/address",
        "/sys/class/net/wlan1/address"
    };
    for (const char* path : paths) {
        std::string mac = read_file(path);
        if (!mac.empty()) {
            mac_address = mac;
            return true;
        }
    }
    return false;
}

std::string hw_normalize_token(const std::string& raw) {
    size_t i = 0, j = raw.size();
    while (i < j && (unsigned char)raw[i] <= 32) ++i;
    while (j > i && (unsigned char)raw[j - 1] <= 32) --j;
    if (i >= j) return "";
    std::string s = raw.substr(i, j - i);
    std::string lower;
    lower.reserve(s.size());
    for (unsigned char c : s) lower.push_back((char)std::tolower(c));
    static const char* junk[] = {"to be filled", "default string", "not specified", "system serial",
                                 "o.e.m.", "xxxxxxxx", "invalid", "unknown", "none"};
    for (const char* t : junk) {
        if (lower.find(t) != std::string::npos) return "";
    }
    return s;
}

bool get_machine_guid(std::string& out) {
    for (const char* name : {"ro.boot.serialno", "ro.serialno",
                             "ro.boot.vbmeta.digest"}) {
        out = hw_normalize_token(get_prop(name));
        if (!out.empty())
            return true;
    }
    out = get_persistent_device_id();
    return !out.empty();
}

bool get_bios_serial(std::string& out) {
    out = get_prop("ro.boot.serialno");
    if (out.empty()) out = get_prop("ro.serialno");
    return !out.empty();
}

bool get_os_disk_serial(std::string& serial) {
    serial = read_file("/sys/block/mmcblk0/device/serial");
    if (!serial.empty()) return true;
    serial = read_file("/sys/block/sda/device/serial");
    if (!serial.empty()) return true;
    serial = read_file("/sys/block/dm-0/device/serial");
    return !serial.empty();
}
