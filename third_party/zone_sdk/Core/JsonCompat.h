#pragma once

#include "nlohmann/json.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <string>


namespace zh_json_compat {

inline const nlohmann::json* Find(const nlohmann::json& object, const char* key) {
	if (!object.is_object())
		return nullptr;
	auto found = object.find(key);
	if (found == object.end() || found->is_null())
		return nullptr;
	return &found.value();
}

inline std::string String(const nlohmann::json& object, const char* key,
	const std::string& fallback = std::string()) {
	const auto* value = Find(object, key);
	if (!value)
		return fallback;
	if (value->is_string())
		return value->get<std::string>();
	if (value->is_boolean())
		return value->get<bool>() ? "true" : "false";
	if (value->is_number())
		return value->dump();
	return fallback;
}

inline long long Int64(const nlohmann::json& object, const char* key, long long fallback = 0) {
	const auto* value = Find(object, key);
	if (!value)
		return fallback;
	try {
		if (value->is_number_unsigned()) {
			const auto number = value->get<unsigned long long>();
			return number <= static_cast<unsigned long long>((std::numeric_limits<long long>::max)())
				? static_cast<long long>(number) : fallback;
		}
		if (value->is_number_integer())
			return value->get<long long>();
		if (value->is_number_float())
			return static_cast<long long>(value->get<double>());
		if (value->is_string()) {
			const auto text = value->get<std::string>();
			size_t used = 0;
			const auto number = std::stoll(text, &used, 10);
			return used == text.size() ? number : fallback;
		}
	}
	catch (...) {
	}
	return fallback;
}

inline int Int(const nlohmann::json& object, const char* key, int fallback = 0) {
	const auto number = Int64(object, key, fallback);
	if (number < (std::numeric_limits<int>::min)() || number > (std::numeric_limits<int>::max)())
		return fallback;
	return static_cast<int>(number);
}

inline bool TryBool(const nlohmann::json& object, const char* key, bool& output) {
	const auto* value = Find(object, key);
	if (!value)
		return false;
	if (value->is_boolean()) {
		output = value->get<bool>();
		return true;
	}
	if (value->is_number()) {
		output = value->get<double>() != 0.0;
		return true;
	}
	if (value->is_string()) {
		auto text = value->get<std::string>();
		std::transform(text.begin(), text.end(), text.begin(),
			[](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
		if (text == "true" || text == "1") {
			output = true;
			return true;
		}
		if (text == "false" || text == "0") {
			output = false;
			return true;
		}
	}
	return false;
}

inline bool Bool(const nlohmann::json& object, const char* key, bool fallback = false) {
	bool value = fallback;
	return TryBool(object, key, value) ? value : fallback;
}

inline std::string ArrayOrEmpty(const nlohmann::json& object, const char* key) {
	const auto* value = Find(object, key);
	if (!value)
		return {};
	if (value->is_array())
		return value->dump();
	if (value->is_string() && value->get_ref<const std::string&>().empty())
		return {};
	return {};
}

} // namespace zh_json_compat
