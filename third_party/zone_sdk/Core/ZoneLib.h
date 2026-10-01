#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <memory>
#include <chrono>
//#include "include/openssl/evp.h"
//#include "include/openssl/aes.h"
//#include "include/openssl/md5.h"
//#include "include/openssl/bio.h"
//#include "include/openssl/buffer.h"
//#include"include/json/json.h"
#include "nlohmann/json.hpp"

#include "../ZoneHelper.h"


class SocketReadMsgContainer {
public:
	std::vector<std::string> read_msg;
	std::mutex lockObject;
};
