#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <memory>
#include <chrono>
#include "./Core/nlohmann/json.hpp"

#pragma region OthStut


// Enumerations
enum class eum_EncryptType {
	AES = 0,
	RC4,
	DES3,
	ChaCha20_en,
	RSA,
	NTRU,
	ECC,
	None,
	Plaintext = 8,
	Base32 = 9,
	Base64 = 10,
	Hex = 11,
};

enum class eum_LoginType {
	Card = 0,
	Account
};

enum class eum_AgreementType {
	HTTP = 0,
	HTTPS,
	SOCKET,
	WebSocket,
	WebSockets
};

/// <summary>业务线路网络分区：1=中国境内，2=中国境外，3=全球。与集群列表项的 net 字段严格一致，仅在匹配项中随机选点。</summary>
enum class eum_NetworkRegion {
	ChinaDomestic = 1,
	Overseas = 2,
	Global = 3
};

/// <summary>集群列表 /api/cluster/list 中的单条端点（各协议数组元素）。</summary>
struct ClusterEndpoint {
	std::string name;
	std::string ip;
	int port = 0;
	std::string host;
	std::string path;
	/// <summary>网络类型：1=中国境内，2=中国境外，3=全球</summary>
	int net = 0;
};

enum class eum_ContactType {
	None = 0,//如果是None,那么修改密码需要原密码
	QQ,
	Email,
	Phone,
	WeChat
};

// C++结构体定义
struct InvSubData {
	std::string Nickname;
	std::string InvitedCode_1;
	std::string InvitedCode_2;
	std::string SoftwarePriceId;
	std::string CommissionData;
	std::string CommissionType;
	std::string Creat_time;
	std::string ChangeType_s;
	std::string ChangeType;
	std::string Notes;

	// Copy constructor
	InvSubData& operator=(const InvSubData& other) {
		if (this == &other) return *this;
		Nickname = other.Nickname;
		InvitedCode_1 = other.InvitedCode_1;
		InvitedCode_2 = other.InvitedCode_2;
		SoftwarePriceId = other.SoftwarePriceId;
		CommissionData = other.CommissionData;
		CommissionType = other.CommissionType;
		Creat_time = other.Creat_time;
		ChangeType_s = other.ChangeType_s;
		ChangeType = other.ChangeType;
		Notes = other.Notes;
		return *this;
	}

	nlohmann::json toJson() const {
		nlohmann::json json;
		json["Nickname"] = Nickname;
		json["InvitedCode_1"] = InvitedCode_1;
		json["InvitedCode_2"] = InvitedCode_2;
		json["SoftwarePriceId"] = SoftwarePriceId;
		json["CommissionData"] = CommissionData;
		json["CommissionType"] = CommissionType;
		json["Creat_time"] = Creat_time;
		json["ChangeType_s"] = ChangeType_s;
		json["ChangeType"] = ChangeType;
		json["Notes"] = Notes;
		return json;
	}

};

// C++结构体定义
struct OnlineClient {
	std::string index;
	std::string key;
	std::string login_time;
	std::string ip;
	std::string mac;
	std::string heart_beat;

	// Copy constructor
	OnlineClient& operator=(const OnlineClient& other) {
		if (this == &other) return *this;
		index = other.index;
		key = other.key;
		login_time = other.login_time;
		ip = other.ip;
		mac = other.mac;
		heart_beat = other.heart_beat;
		return *this;
	}

	// 反序列化构造函数
	void fromJson(const nlohmann::json& json) {
		//OnlineClient client;
		index = json["index"].get<std::string>();
		key = json["key"].get<std::string>();
		login_time = json["login_time"].get<std::string>();
		ip = json["ip"].get<std::string>();
		mac = json["mac"].get<std::string>();
		heart_beat = json["heart_beat"].get<std::string>();
		//return client;
	}

	nlohmann::json toJson() const {
		nlohmann::json json;
		json["index"] = index;
		json["key"] = key;
		json["login_time"] = login_time;
		json["ip"] = ip;
		json["mac"] = mac;
		json["heart_beat"] = heart_beat;
		return json;
	}

};

struct OnlineClientData {
	std::vector<OnlineClient>Clients;

	// Copy constructor
	OnlineClientData& operator=(const OnlineClientData& other) {
		if (this == &other) return *this;
		Clients = other.Clients;
		return *this;
	}

	// 反序列化构造函数
	void fromJson(const nlohmann::json& json) {
		for (const auto& clientJson : json["clients"]) {
			OnlineClient tmp_OneClient;
			tmp_OneClient.fromJson(clientJson);
			Clients.push_back(tmp_OneClient);
		}
	}

	nlohmann::json toJson() const {
		nlohmann::json json;
		for (const auto& client : Clients) {
			json["Clients"].push_back(client.toJson());
		}
		return json;
	}


};


// Server结构体
struct Server {
	std::string server_id;
	std::string http_address;
	std::string https_address;
	std::string socket_address;
	std::string ws_address;
	std::string wss_address;
	std::string latency_ms;
	std::string load_rate;
	std::string load_level;
	std::string heartbeat_frequency_s;
	std::string curtime_s;
	std::string curtime_ms;
	std::string status;
	std::string last_updated;
	std::string error_rate;
	std::string server_location_name;
	std::string server_location_lon;
	std::string server_location_lat;
	std::string post_limit;
	std::string firewall;
	std::string os_version;
	std::string software_version;
	std::string maintenance_mode;
	/// <summary>网络类型：1=中国境内，2=中国境外，3=全球（集群/列表接口可选字段）</summary>
	int net = 0;

	// Copy constructor
	Server& operator=(const Server& other) {
		if (this == &other) {
			return *this;  // Handle self-assignment
		}

		server_id = other.server_id;
		http_address = other.http_address;
		https_address = other.https_address;
		socket_address = other.socket_address;
		ws_address = other.ws_address;
		wss_address = other.wss_address;
		latency_ms = other.latency_ms;
		load_rate = other.load_rate;
		load_level = other.load_level;
		heartbeat_frequency_s = other.heartbeat_frequency_s;
		curtime_s = other.curtime_s;
		curtime_ms = other.curtime_ms;
		status = other.status;
		last_updated = other.last_updated;
		error_rate = other.error_rate;
		server_location_name = other.server_location_name;
		server_location_lon = other.server_location_lon;
		server_location_lat = other.server_location_lat;
		post_limit = other.post_limit;
		firewall = other.firewall;
		os_version = other.os_version;
		software_version = other.software_version;
		maintenance_mode = other.maintenance_mode;
		net = other.net;

		return *this;
	}

	// 自定义的fromJson函数
	void fromJson(const nlohmann::json& j) {
		server_id = j.at("server_id").get<std::string>();
		http_address = j.at("http_address").get<std::string>();
		https_address = j.at("https_address").get<std::string>();
		socket_address = j.at("socket_address").get<std::string>();
		ws_address = j.at("ws_address").get<std::string>();
		wss_address = j.at("wss_address").get<std::string>();
		latency_ms = j.at("latency_ms").get<std::string>();
		load_rate = j.at("load_rate").get<std::string>();
		load_level = j.at("load_level").get<std::string>();
		heartbeat_frequency_s = j.at("heartbeat_frequency_s").get<std::string>();
		curtime_s = j.at("curtime_s").get<std::string>();
		curtime_ms = j.at("curtime_ms").get<std::string>();
		status = j.at("status").get<std::string>();
		last_updated = j.at("last_updated").get<std::string>();
		error_rate = j.at("error_rate").get<std::string>();
		server_location_name = j.at("server_location_name").get<std::string>();
		server_location_lon = j.at("server_location_lon").get<std::string>();
		server_location_lat = j.at("server_location_lat").get<std::string>();
		post_limit = j.at("post_limit").get<std::string>();
		firewall = j.at("firewall").get<std::string>();
		os_version = j.at("os_version").get<std::string>();
		software_version = j.at("software_version").get<std::string>();
		maintenance_mode = j.at("maintenance_mode").get<std::string>();
		net = j.value("net", 0);
	}

	// 自定义的 toJson 函数
	nlohmann::json toJson() const {
		return nlohmann::json{
			{"server_id", server_id},
			{"http_address", http_address},
			{"https_address", https_address},
			{"socket_address", socket_address},
			{"ws_address", ws_address},
			{"wss_address", wss_address},
			{"latency_ms", latency_ms},
			{"load_rate", load_rate},
			{"load_level", load_level},
			{"heartbeat_frequency_s", heartbeat_frequency_s},
			{"curtime_s", curtime_s},
			{"curtime_ms", curtime_ms},
			{"status", status},
			{"last_updated", last_updated},
			{"error_rate", error_rate},
			{"server_location_name", server_location_name},
			{"server_location_lon", server_location_lon},
			{"server_location_lat", server_location_lat},
			{"post_limit", post_limit},
			{"firewall", firewall},
			{"os_version", os_version},
			{"software_version", software_version},
			{"maintenance_mode", maintenance_mode},
			{"net", net}
		};
	}
};
// SvrData结构体
struct SvrData {
	std::string cluster_status;
	std::string average_latency_ms;
	std::string average_load_rate;
	std::string total_servers;
	std::string curtime_s;
	std::string curtime_ms;
	std::string error_rate;
	std::string overall_data_center_status;
	std::string cluster_maintenance_mode;
	std::string last_cluster_update;
	std::vector<Server> server_cluster;

	// Copy constructor
	SvrData& operator=(const SvrData& other) {
		if (this == &other) {
			return *this;  // Handle self-assignment
		}

		cluster_status = other.cluster_status;
		average_latency_ms = other.average_latency_ms;
		average_load_rate = other.average_load_rate;
		total_servers = other.total_servers;
		curtime_s = other.curtime_s;
		curtime_ms = other.curtime_ms;
		error_rate = other.error_rate;
		overall_data_center_status = other.overall_data_center_status;
		cluster_maintenance_mode = other.cluster_maintenance_mode;
		last_cluster_update = other.last_cluster_update;

		// Copying the vector of Server objects
		server_cluster = other.server_cluster;

		return *this;
	}

	// 自定义的fromJson函数
	void fromJson(const nlohmann::json& j) {
		cluster_status = j.at("cluster_status").get<std::string>();
		average_latency_ms = j.at("average_latency_ms").get<std::string>();
		average_load_rate = j.at("average_load_rate").get<std::string>();
		total_servers = j.at("total_servers").get<std::string>();
		curtime_s = j.at("curtime_s").get<std::string>();
		curtime_ms = j.at("curtime_ms").get<std::string>();
		error_rate = j.at("error_rate").get<std::string>();
		overall_data_center_status = j.at("overall_data_center_status").get<std::string>();
		cluster_maintenance_mode = j.at("cluster_maintenance_mode").get<std::string>();
		last_cluster_update = j.at("last_cluster_update").get<std::string>();

		// 处理server_cluster数组
		if (j.contains("server_cluster")) {
			for (const auto& item : j["server_cluster"]) {
				Server server;
				server.fromJson(item); // 调用Server的fromJson来反序列化每个server对象
				server_cluster.push_back(server);
			}
		}
	}

	// 自定义的 toJson 函数
	nlohmann::json toJson() const {
		// 序列化 server_cluster 数组
		std::vector<nlohmann::json> serversJson;
		for (const auto& server : server_cluster) {
			serversJson.push_back(server.toJson());
		}

		return nlohmann::json{
			{"cluster_status", cluster_status},
			{"average_latency_ms", average_latency_ms},
			{"average_load_rate", average_load_rate},
			{"total_servers", total_servers},
			{"curtime_s", curtime_s},
			{"curtime_ms", curtime_ms},
			{"error_rate", error_rate},
			{"overall_data_center_status", overall_data_center_status},
			{"cluster_maintenance_mode", cluster_maintenance_mode},
			{"last_cluster_update", last_cluster_update},
			{"server_cluster", serversJson}
		};
	}
};

struct Level {
	int exp;
	std::string name;
	int point_extern;
	int point_exp;
	int ex_time;
	int ex_nums;

	// 赋值运算符
	Level& operator=(const Level& other) {
		if (this == &other) return *this;
		exp = other.exp;
		name = other.name;
		point_extern = other.point_extern;
		point_exp = other.point_exp;
		ex_time = other.ex_time;
		ex_nums = other.ex_nums;
		return *this;
	}

	// 转换为JSON对象
	nlohmann::json toJson() const {
		nlohmann::json json;
		json["exp"] = exp;
		json["name"] = name;
		json["point_extern"] = point_extern;
		json["point_exp"] = point_exp;
		json["ex_time"] = ex_time;
		json["ex_nums"] = ex_nums;
		return json;
	}
};

struct Rules {
	int rule_type;
	std::string rule_value;
	int reward_points;
	int reward_exp;
	int reward_time;
	int reward_nums;
	std::string description;
	int item_type;
	int item_value;
	std::string image;
	std::string name;

	// 赋值运算符
	Rules& operator=(const Rules& other) {
		if (this == &other) return *this;
		rule_type = other.rule_type;
		rule_value = other.rule_value;
		reward_points = other.reward_points;
		reward_exp = other.reward_exp;
		reward_time = other.reward_time;
		reward_nums = other.reward_nums;
		description = other.description;
		item_type = other.item_type;
		item_value = other.item_value;
		image = other.image;
		name = other.name;
		return *this;
	}

	// 转换为JSON对象
	nlohmann::json toJson() const {
		nlohmann::json json;
		json["rule_type"] = rule_type;
		json["rule_value"] = rule_value;
		json["reward_points"] = reward_points;
		json["reward_exp"] = reward_exp;
		json["reward_time"] = reward_time;
		json["reward_nums"] = reward_nums;
		json["description"] = description;
		json["item_type"] = item_type;
		json["item_value"] = item_value;
		json["image"] = image;
		json["name"] = name;
		return json;
	}
};

struct Data_signin {
	int _id;
	Level level;
	std::vector<Rules> rules;
	int reward_points;
	int reward_exp;
	int reward_time;
	int reward_nums;
	std::string mac;
	std::string macName;
	int creat_time;
	std::string status;
	std::string IP;

	// 赋值运算符
	Data_signin& operator=(const Data_signin& other) {
		if (this == &other) return *this;
		_id = other._id;
		level = other.level;
		rules = other.rules;
		reward_points = other.reward_points;
		reward_exp = other.reward_exp;
		reward_time = other.reward_time;
		reward_nums = other.reward_nums;
		mac = other.mac;
		macName = other.macName;
		creat_time = other.creat_time;
		status = other.status;
		IP = other.IP;
		return *this;
	}

	// 转换为JSON对象
	nlohmann::json toJson() const {
		nlohmann::json json;
		json["_id"] = _id;
		json["level"] = level.toJson();  // 假设Level结构体也有toJson方法
		json["rules"] = nlohmann::json::array();
		for (const auto& rule : rules) {
			json["rules"].push_back(rule.toJson());  // 假设Rules结构体也有toJson方法
		}
		json["reward_points"] = reward_points;
		json["reward_exp"] = reward_exp;
		json["reward_time"] = reward_time;
		json["reward_nums"] = reward_nums;
		json["mac"] = mac;
		json["macName"] = macName;
		json["creat_time"] = creat_time;
		json["status"] = status;
		json["IP"] = IP;
		return json;
	}
};
struct Data_grade {
	std::string exp;
	std::string name;
	std::string point_extern;
	std::string point_exp;
	std::string ex_time;
	std::string ex_nums;

	// 赋值运算符
	Data_grade& operator=(const Data_grade& other) {
		if (this == &other) return *this;
		exp = other.exp;
		name = other.name;
		point_extern = other.point_extern;
		point_exp = other.point_exp;
		ex_time = other.ex_time;
		ex_nums = other.ex_nums;
		return *this;
	}

	// 转换为JSON对象
	nlohmann::json toJson() const {
		nlohmann::json json;
		json["exp"] = exp;
		json["name"] = name;
		json["point_extern"] = point_extern;
		json["point_exp"] = point_exp;
		json["ex_time"] = ex_time;
		json["ex_nums"] = ex_nums;
		return json;
	}
};

struct Lotteryi {
	std::string name;
	std::string desc;
	std::string type;
	std::string value;
	std::string probability;
	std::string guaranteed;
	std::string image;

	// 赋值运算符
	Lotteryi& operator=(const Lotteryi& other) {
		if (this == &other) return *this;
		name = other.name;
		desc = other.desc;
		type = other.type;
		value = other.value;
		probability = other.probability;
		guaranteed = other.guaranteed;
		image = other.image;
		return *this;
	}

	// 转换为JSON对象
	nlohmann::json toJson() const {
		nlohmann::json json;
		json["name"] = name;
		json["desc"] = desc;
		json["type"] = type;
		json["value"] = value;
		json["probability"] = probability;
		json["guaranteed"] = guaranteed;
		json["image"] = image;
		return json;
	}
};
struct Lot_data {
	std::string item_name;
	std::string item_type;
	std::string item_value;
	std::string item_desc;
	std::string image;
	std::string cost_points;
	std::string reward_exp;
	std::string is_free;
	std::string is_guarantee;

	// 赋值运算符
	Lot_data& operator=(const Lot_data& other) {
		if (this == &other) return *this;
		item_name = other.item_name;
		item_type = other.item_type;
		item_value = other.item_value;
		item_desc = other.item_desc;
		image = other.image;
		cost_points = other.cost_points;
		reward_exp = other.reward_exp;
		is_free = other.is_free;
		is_guarantee = other.is_guarantee;
		return *this;
	}

	// 转换为JSON对象
	nlohmann::json toJson() const {
		nlohmann::json json;
		json["item_name"] = item_name;
		json["item_type"] = item_type;
		json["item_value"] = item_value;
		json["item_desc"] = item_desc;
		json["image"] = image;
		json["cost_points"] = cost_points;
		json["reward_exp"] = reward_exp;
		json["is_free"] = is_free;
		json["is_guarantee"] = is_guarantee;
		return json;
	}
};
struct Loth_data {
	std::string id;
	std::string name;
	std::string creat_time;
	std::string type;
	std::string value;
	std::string is_guaranteed;
	std::string ip;
	std::string mac;
	std::string mac_name;
	std::string Free;

	// 赋值运算符
	Loth_data& operator=(const Loth_data& other) {
		if (this == &other) return *this;
		id = other.id;
		name = other.name;
		creat_time = other.creat_time;
		type = other.type;
		value = other.value;
		is_guaranteed = other.is_guaranteed;
		ip = other.ip;
		mac = other.mac;
		mac_name = other.mac_name;
		Free = other.Free;
		return *this;
	}

	// 转换为JSON对象
	nlohmann::json toJson() const {
		nlohmann::json json;
		json["id"] = id;
		json["name"] = name;
		json["creat_time"] = creat_time;
		json["type"] = type;
		json["value"] = value;
		json["is_guaranteed"] = is_guaranteed;
		json["ip"] = ip;
		json["mac"] = mac;
		json["mac_name"] = mac_name;
		json["Free"] = Free;
		return json;
	}
};
struct Data_shop {
	std::string id;
	std::string name;
	std::string description;
	std::string creat_time;
	std::string points;
	std::string exp;
	std::string type;
	std::string value;
	std::string image;
	std::string status;

	// 赋值运算符
	Data_shop& operator=(const Data_shop& other) {
		if (this == &other) return *this;
		id = other.id;
		name = other.name;
		description = other.description;
		creat_time = other.creat_time;
		points = other.points;
		exp = other.exp;
		type = other.type;
		value = other.value;
		image = other.image;
		status = other.status;
		return *this;
	}

	// 转换为JSON对象
	nlohmann::json toJson() const {
		nlohmann::json json;
		json["id"] = id;
		json["name"] = name;
		json["description"] = description;
		json["creat_time"] = creat_time;
		json["points"] = points;
		json["exp"] = exp;
		json["type"] = type;
		json["value"] = value;
		json["image"] = image;
		json["status"] = status;
		return json;
	}
};
struct Data_shop_history {
	std::string id;
	std::string name;
	std::string description;
	std::string need_exp;
	std::string type;
	std::string value;
	std::string creat_time;
	std::string status;
	std::string ip;
	std::string mac;
	std::string mac_name;

	// 赋值运算符
	Data_shop_history& operator=(const Data_shop_history& other) {
		if (this == &other) return *this;
		id = other.id;
		name = other.name;
		description = other.description;
		need_exp = other.need_exp;
		type = other.type;
		value = other.value;
		creat_time = other.creat_time;
		status = other.status;
		ip = other.ip;
		mac = other.mac;
		mac_name = other.mac_name;
		return *this;
	}

	// 转换为JSON对象
	nlohmann::json toJson() const {
		nlohmann::json json;
		json["id"] = id;
		json["name"] = name;
		json["description"] = description;
		json["need_exp"] = need_exp;
		json["type"] = type;
		json["value"] = value;
		json["creat_time"] = creat_time;
		json["status"] = status;
		json["ip"] = ip;
		json["mac"] = mac;
		json["mac_name"] = mac_name;
		return json;
	}
};






struct DataObject {
	std::string Token;
	std::string ExpirationTime;
	std::string ExpirationNum;
	std::string ExpirationTimeHeartBeat;
	std::string Message;
	std::string Message2;
	std::string Title;
	std::string value;
	std::string Status;
	std::string Run_status;
	long Current_Score = 0;

	std::string New_version;
	std::string New_notice;
	std::string New_downloadurl;
	std::string New_downloadpwd;
	std::string SoftwareName;
	std::string SoftwareVer;
	std::string LoginType;
	std::string Probation;
	std::string InvitationMode;
	std::string VerifyMode;
	std::string Notice;
	std::string Account;
	std::string Password;
	std::string CardHead;
	std::string Card;

	std::string CapacityForTime;
	std::string CapacityForNum;
	std::string Use_time;
	std::string UsedMacCode;
	std::string UsedIp;
	std::string UsedMachineName;
	std::string UsedMacCodeList;
	std::string UsedIpList;
	std::string Use_timeList;
	std::string UsedMachineNameList;
	std::string Unbind;

	std::string PriceName;
	std::string PriceTypeStr;
	std::string PriceType;
	std::string PriceNum;
	std::string PriceUnbind;

	std::string ClientCfgId;
	std::string ClientInvitationCode;
	std::string ClientInvitationCodeB;
	std::string RefillCardList;

	std::string VerifyID;
	std::string VerifyData;
	std::string InvitationCode;
	std::string Harvest;
	std::string Inv_count;
	std::vector<InvSubData> InvitationSubData;

	std::string Timestamp;
	std::string Timestamp_ms;
	std::string Datetime_1;
	std::string Datetime_2;
	std::string Week_1;
	std::string Week_2;
	std::string Week_3;
	std::string Week_4;

	std::string OldDevice;
	std::string AutoUbndDeT;
	std::string AutoUbndDeS;
	std::string UnBind;
	std::string Points;
	std::string Experience;
	std::string SupCard;
	std::string LoginStatus;
	std::string FirstLogin;
	std::string AutoExUbnd;
	std::string OnlineCount;
	std::string FirstRewardScore;
	std::string FirstRewardTime;
	std::string RegRewardScore;
	std::string RegRewardTime;
	std::string RegStatus;
	std::string UbndDeT;
	std::string UbndDeS;
	std::string UnBindStatus;
	std::string SubNum;
	std::string SubSs;
	std::string OnlineUser;
	std::string OnlineUserMult;
	std::string OnlineTourist;
	std::string OnlineTouristMult;
	std::string VerStatus;
	std::string RechargeStatus;
	std::string HbStatus;
	std::string CloudeLastTimeRead;
	std::string CloudeLastTimeWrite;
	std::string CloudeCountRead;
	std::string CloudeCountWrite;
	std::string ExStatus;
	std::string ExLogout;
	std::string ExOnlineDev;
	OnlineClientData online_client;
	std::string kick_record;
	SvrData svr_data;

	std::string row_count;
	std::vector<Data_signin> data_signin;
	std::vector<Data_grade> data_grade;
	std::string name;
	std::string url;
	std::string cost_points;
	std::string reward_exp;
	std::string free_draws_day;
	std::string guarantee_draws;
	std::string use_draws_day;
	std::string lave_draws_day;
	std::vector<Lotteryi> lotteryi;
	std::vector<Lot_data> lot_data;
	std::vector<Loth_data> loth_data;
	std::vector<Data_shop> data_shop;
	std::string item_name;
	std::string item_type;
	std::string item_value;
	std::string item_desc;
	std::vector<Data_shop_history> data_shop_history;

	/// SDK 1001 新接口字段追加在旧结构末尾，保留已有字段顺序。
	std::string RawJson;
	/// DownloadCloudFile 返回的真实下载地址。
	std::string DownloadUrl;
	std::string AuthorizationId;
	std::string FileId;
	std::string VersionId;
	std::string Version;
	std::string FileName;
	long long SizeBytes = 0;
	std::string Md5;
	std::string Sha256;
	std::string ContentType;
	std::string DeliveryChannel;
	std::string BillingRegion;
	long long ChargedTrafficBytes = 0;
	long long ExpiresAtUnix = 0;
	bool HasChargedAgain = false;
	bool ChargedAgain = false;
	long long RowCount = 0;
	int Page = 0;
	int PageSize = 0;
	bool HasMore = false;
	std::string VersionsJson;
	std::string FeedbackItemsJson;



	// 完善的拷贝赋值运算符
	DataObject& operator=(const DataObject& other) {
		if (this == &other) return *this;

		// 基础信息
		Token = other.Token;
		ExpirationTime = other.ExpirationTime;
		ExpirationNum = other.ExpirationNum;
		ExpirationTimeHeartBeat = other.ExpirationTimeHeartBeat;
		Message = other.Message;
		Message2 = other.Message2;
		Title = other.Title;
		value = other.value;
		Status = other.Status;
		Run_status = other.Run_status;
		Current_Score = other.Current_Score;

		// 版本和软件信息
		New_version = other.New_version;
		New_notice = other.New_notice;
		New_downloadurl = other.New_downloadurl;
		New_downloadpwd = other.New_downloadpwd;
		SoftwareName = other.SoftwareName;
		SoftwareVer = other.SoftwareVer;
		LoginType = other.LoginType;
		Probation = other.Probation;
		InvitationMode = other.InvitationMode;
		VerifyMode = other.VerifyMode;
		Notice = other.Notice;
		Account = other.Account;
		Password = other.Password;
		CardHead = other.CardHead;
		Card = other.Card;

		// 使用容量信息
		CapacityForTime = other.CapacityForTime;
		CapacityForNum = other.CapacityForNum;
		Use_time = other.Use_time;
		UsedMacCode = other.UsedMacCode;
		UsedIp = other.UsedIp;
		UsedMachineName = other.UsedMachineName;
		UsedMacCodeList = other.UsedMacCodeList;
		UsedIpList = other.UsedIpList;
		Use_timeList = other.Use_timeList;
		UsedMachineNameList = other.UsedMachineNameList;
		Unbind = other.Unbind;
		Points = other.Points;
		Experience = other.Experience;
		SupCard = other.SupCard;

		// 价格信息
		PriceName = other.PriceName;
		PriceTypeStr = other.PriceTypeStr;
		PriceType = other.PriceType;
		PriceNum = other.PriceNum;
		PriceUnbind = other.PriceUnbind;

		// 客户端配置
		ClientCfgId = other.ClientCfgId;
		ClientInvitationCode = other.ClientInvitationCode;
		ClientInvitationCodeB = other.ClientInvitationCodeB;
		RefillCardList = other.RefillCardList;

		// 验证和邀请信息
		VerifyID = other.VerifyID;
		VerifyData = other.VerifyData;
		InvitationCode = other.InvitationCode;
		Harvest = other.Harvest;
		Inv_count = other.Inv_count;
		InvitationSubData = other.InvitationSubData;

		// 时间信息
		Timestamp = other.Timestamp;
		Timestamp_ms = other.Timestamp_ms;
		Datetime_1 = other.Datetime_1;
		Datetime_2 = other.Datetime_2;
		Week_1 = other.Week_1;
		Week_2 = other.Week_2;
		Week_3 = other.Week_3;
		Week_4 = other.Week_4;

		// 设备和登录状态
		OldDevice = other.OldDevice;
		AutoUbndDeT = other.AutoUbndDeT;
		AutoUbndDeS = other.AutoUbndDeS;
		UnBind = other.UnBind;
		LoginStatus = other.LoginStatus;
		FirstLogin = other.FirstLogin;
		AutoExUbnd = other.AutoExUbnd;
		OnlineCount = other.OnlineCount;
		FirstRewardScore = other.FirstRewardScore;
		FirstRewardTime = other.FirstRewardTime;
		RegRewardScore = other.RegRewardScore;
		RegRewardTime = other.RegRewardTime;
		RegStatus = other.RegStatus;
		UbndDeT = other.UbndDeT;
		UbndDeS = other.UbndDeS;
		UnBindStatus = other.UnBindStatus;
		SubNum = other.SubNum;
		SubSs = other.SubSs;
		OnlineUser = other.OnlineUser;
		OnlineUserMult = other.OnlineUserMult;
		OnlineTourist = other.OnlineTourist;
		OnlineTouristMult = other.OnlineTouristMult;
		VerStatus = other.VerStatus;
		RechargeStatus = other.RechargeStatus;
		HbStatus = other.HbStatus;
		CloudeLastTimeRead = other.CloudeLastTimeRead;
		CloudeLastTimeWrite = other.CloudeLastTimeWrite;
		CloudeCountRead = other.CloudeCountRead;
		CloudeCountWrite = other.CloudeCountWrite;
		ExStatus = other.ExStatus;
		ExLogout = other.ExLogout;
		ExOnlineDev = other.ExOnlineDev;
		online_client = other.online_client;
		kick_record = other.kick_record;
		RawJson = other.RawJson;
		DownloadUrl = other.DownloadUrl;
		AuthorizationId = other.AuthorizationId;
		FileId = other.FileId;
		VersionId = other.VersionId;
		Version = other.Version;
		FileName = other.FileName;
		SizeBytes = other.SizeBytes;
		Md5 = other.Md5;
		Sha256 = other.Sha256;
		ContentType = other.ContentType;
		DeliveryChannel = other.DeliveryChannel;
		BillingRegion = other.BillingRegion;
		ChargedTrafficBytes = other.ChargedTrafficBytes;
		ExpiresAtUnix = other.ExpiresAtUnix;
		HasChargedAgain = other.HasChargedAgain;
		ChargedAgain = other.ChargedAgain;
		RowCount = other.RowCount;
		Page = other.Page;
		PageSize = other.PageSize;
		HasMore = other.HasMore;
		VersionsJson = other.VersionsJson;
		FeedbackItemsJson = other.FeedbackItemsJson;
		svr_data = other.svr_data;

		// 补充之前遗漏的属性
		row_count = other.row_count;
		data_signin = other.data_signin;
		data_grade = other.data_grade;
		name = other.name;
		url = other.url;
		cost_points = other.cost_points;
		reward_exp = other.reward_exp;
		free_draws_day = other.free_draws_day;
		guarantee_draws = other.guarantee_draws;
		use_draws_day = other.use_draws_day;
		lave_draws_day = other.lave_draws_day;
		lotteryi = other.lotteryi;
		lot_data = other.lot_data;
		loth_data = other.loth_data;
		data_shop = other.data_shop;
		item_name = other.item_name;
		item_type = other.item_type;
		item_value = other.item_value;
		item_desc = other.item_desc;
		data_shop_history = other.data_shop_history;

		return *this;
	}

	// 完善的toJson方法
	nlohmann::json toJson() const {
		nlohmann::json json;

		// 基础信息
		json["Token"] = Token;
		json["ExpirationTime"] = ExpirationTime;
		json["ExpirationNum"] = ExpirationNum;
		json["ExpirationTimeHeartBeat"] = ExpirationTimeHeartBeat;
		json["Message"] = Message;
		json["Message2"] = Message2;
		json["Title"] = Title;
		json["value"] = value;
		json["Status"] = Status;
		json["Run_status"] = Run_status;
		json["RawJson"] = RawJson;
		json["DownloadUrl"] = DownloadUrl;
		json["AuthorizationId"] = AuthorizationId;
		json["FileId"] = FileId;
		json["VersionId"] = VersionId;
		json["Version"] = Version;
		json["FileName"] = FileName;
		json["SizeBytes"] = SizeBytes;
		json["Md5"] = Md5;
		json["Sha256"] = Sha256;
		json["ContentType"] = ContentType;
		json["DeliveryChannel"] = DeliveryChannel;
		json["BillingRegion"] = BillingRegion;
		json["ChargedTrafficBytes"] = ChargedTrafficBytes;
		json["ExpiresAtUnix"] = ExpiresAtUnix;
		json["HasChargedAgain"] = HasChargedAgain;
		json["ChargedAgain"] = ChargedAgain;
		json["RowCount"] = RowCount;
		json["Page"] = Page;
		json["PageSize"] = PageSize;
		json["HasMore"] = HasMore;
		json["VersionsJson"] = VersionsJson;
		json["FeedbackItemsJson"] = FeedbackItemsJson;
		json["Current_Score"] = Current_Score;

		// 版本和软件信息
		json["New_version"] = New_version;
		json["New_notice"] = New_notice;
		json["New_downloadurl"] = New_downloadurl;
		json["New_downloadpwd"] = New_downloadpwd;
		json["SoftwareName"] = SoftwareName;
		json["SoftwareVer"] = SoftwareVer;
		json["LoginType"] = LoginType;
		json["Probation"] = Probation;
		json["InvitationMode"] = InvitationMode;
		json["VerifyMode"] = VerifyMode;
		json["Notice"] = Notice;
		json["Account"] = Account;
		json["Password"] = Password;
		json["CardHead"] = CardHead;
		json["Card"] = Card;

		// 使用容量信息
		json["CapacityForTime"] = CapacityForTime;
		json["CapacityForNum"] = CapacityForNum;
		json["Use_time"] = Use_time;
		json["UsedMacCode"] = UsedMacCode;
		json["UsedIp"] = UsedIp;
		json["UsedMachineName"] = UsedMachineName;
		json["UsedMacCodeList"] = UsedMacCodeList;
		json["UsedIpList"] = UsedIpList;
		json["Use_timeList"] = Use_timeList;
		json["UsedMachineNameList"] = UsedMachineNameList;
		json["Unbind"] = Unbind;
		json["Points"] = Points;
		json["Experience"] = Experience;
		json["SupCard"] = SupCard;

		// 价格信息
		json["PriceName"] = PriceName;
		json["PriceTypeStr"] = PriceTypeStr;
		json["PriceType"] = PriceType;
		json["PriceNum"] = PriceNum;
		json["PriceUnbind"] = PriceUnbind;

		// 客户端配置
		json["ClientCfgId"] = ClientCfgId;
		json["ClientInvitationCode"] = ClientInvitationCode;
		json["ClientInvitationCodeB"] = ClientInvitationCodeB;
		json["RefillCardList"] = RefillCardList;

		// 验证和邀请信息
		json["VerifyID"] = VerifyID;
		json["VerifyData"] = VerifyData;
		json["InvitationCode"] = InvitationCode;
		json["Harvest"] = Harvest;
		json["Inv_count"] = Inv_count;

		// 处理InvitationSubData数组
		nlohmann::json invSubDataArray = nlohmann::json::array();
		for (const auto& invSubData : InvitationSubData) {
			invSubDataArray.push_back(invSubData.toJson());
		}
		json["InvitationSubData"] = invSubDataArray;

		// 时间信息
		json["Timestamp"] = Timestamp;
		json["Timestamp_ms"] = Timestamp_ms;
		json["Datetime_1"] = Datetime_1;
		json["Datetime_2"] = Datetime_2;
		json["Week_1"] = Week_1;
		json["Week_2"] = Week_2;
		json["Week_3"] = Week_3;
		json["Week_4"] = Week_4;

		// 设备和登录状态
		json["OldDevice"] = OldDevice;
		json["AutoUbndDeT"] = AutoUbndDeT;
		json["AutoUbndDeS"] = AutoUbndDeS;
		json["UnBind"] = UnBind;
		json["LoginStatus"] = LoginStatus;
		json["FirstLogin"] = FirstLogin;
		json["AutoExUbnd"] = AutoExUbnd;
		json["OnlineCount"] = OnlineCount;
		json["FirstRewardScore"] = FirstRewardScore;
		json["FirstRewardTime"] = FirstRewardTime;
		json["RegRewardScore"] = RegRewardScore;
		json["RegRewardTime"] = RegRewardTime;
		json["RegStatus"] = RegStatus;
		json["UbndDeT"] = UbndDeT;
		json["UbndDeS"] = UbndDeS;
		json["UnBindStatus"] = UnBindStatus;
		json["SubNum"] = SubNum;
		json["SubSs"] = SubSs;
		json["OnlineUser"] = OnlineUser;
		json["OnlineUserMult"] = OnlineUserMult;
		json["OnlineTourist"] = OnlineTourist;
		json["OnlineTouristMult"] = OnlineTouristMult;
		json["VerStatus"] = VerStatus;
		json["RechargeStatus"] = RechargeStatus;
		json["HbStatus"] = HbStatus;
		json["CloudeLastTimeRead"] = CloudeLastTimeRead;
		json["CloudeLastTimeWrite"] = CloudeLastTimeWrite;
		json["CloudeCountRead"] = CloudeCountRead;
		json["CloudeCountWrite"] = CloudeCountWrite;
		json["ExStatus"] = ExStatus;
		json["ExLogout"] = ExLogout;
		json["ExOnlineDev"] = ExOnlineDev;
		json["online_client"] = online_client.toJson();
		json["kick_record"] = kick_record;
		json["svr_data"] = svr_data.toJson();

		// 补充之前遗漏的属性
		json["row_count"] = row_count;

		// 处理data_signin数组
		nlohmann::json signinArray = nlohmann::json::array();
		for (const auto& signin : data_signin) {
			signinArray.push_back(signin.toJson());
		}
		json["data_signin"] = signinArray;

		// 处理data_grade数组
		nlohmann::json gradeArray = nlohmann::json::array();
		for (const auto& grade : data_grade) {
			gradeArray.push_back(grade.toJson());
		}
		json["data_grade"] = gradeArray;

		json["name"] = name;
		json["url"] = url;
		json["cost_points"] = cost_points;
		json["reward_exp"] = reward_exp;
		json["free_draws_day"] = free_draws_day;
		json["guarantee_draws"] = guarantee_draws;
		json["use_draws_day"] = use_draws_day;
		json["lave_draws_day"] = lave_draws_day;

		// 处理lotteryi数组
		nlohmann::json lotteryiArray = nlohmann::json::array();
		for (const auto& lot : lotteryi) {
			lotteryiArray.push_back(lot.toJson());
		}
		json["lotteryi"] = lotteryiArray;

		// 处理lot_data数组
		nlohmann::json lotDataArray = nlohmann::json::array();
		for (const auto& data : lot_data) {
			lotDataArray.push_back(data.toJson());
		}
		json["lot_data"] = lotDataArray;

		// 处理loth_data数组
		nlohmann::json lothDataArray = nlohmann::json::array();
		for (const auto& data : loth_data) {
			lothDataArray.push_back(data.toJson());
		}
		json["loth_data"] = lothDataArray;

		// 处理data_shop数组
		nlohmann::json shopArray = nlohmann::json::array();
		for (const auto& shop : data_shop) {
			shopArray.push_back(shop.toJson());
		}
		json["data_shop"] = shopArray;

		json["item_name"] = item_name;
		json["item_type"] = item_type;
		json["item_value"] = item_value;
		json["item_desc"] = item_desc;

		// 处理data_shop_history数组
		nlohmann::json shopHistoryArray = nlohmann::json::array();
		for (const auto& history : data_shop_history) {
			shopHistoryArray.push_back(history.toJson());
		}
		json["data_shop_history"] = shopHistoryArray;

		return json;
	}
};

struct ApiResponse {
	std::string Status;
	std::string Message;
	std::string Code;
	DataObject Data;
	std::string Soft_encrypt_data;
	std::string Soft_id;
	std::string Time;
	std::string Sign;

	// Copy constructor
	ApiResponse& operator=(const ApiResponse& other) {
		if (this == &other) return *this;
		Status = other.Status;
		Message = other.Message;
		Code = other.Code;
		Data = other.Data;
		Soft_encrypt_data = other.Soft_encrypt_data;
		Soft_id = other.Soft_id;
		Time = other.Time;
		Sign = other.Sign;
		return *this;
	}

	nlohmann::json toJson() const {
		nlohmann::json json;
		json["Status"] = Status;
		json["Message"] = Message;
		json["Code"] = Code;
		json["Data"] = Data.toJson();
		json["Soft_encrypt_data"] = Soft_encrypt_data;
		json["Soft_id"] = Soft_id;
		json["Time"] = Time;
		json["Sign"] = Sign;
		return json;
	}
};

#pragma endregion

#ifndef ZH_SDK_VER_STR
#define ZH_SDK_VER_STR "1001"
#endif

class ZoneHelper
{
public:
	/// <summary>
	/// ZoneHelper初始化参数,必须首先调用初始化
	/// </summary>
	/// <param name="arg_SoftwareId">客户端ID</param>
	/// <param name="arg_soft_ver">软件版本号</param>
	/// <param name="arg_EncryptKey">加密key</param>
	/// <param name="arg_EncryptIv">加密iv</param>
	/// <param name="arg_encryptType">加密类型:0=AES,1=RC4,2=DES3,3=ChaCha20,4=RSA,5=NTRU,6=ECC</param>
	/// <param name="arg_LoginType">登录方式:0=Card,1=Account</param>
	/// <param name="arg_AgreementType">通讯协议:0=HTTP,1=HTTPS,2=SOCKET,3=WebSocket,4=WebSockets</param>
	/// <param name="arg_NetworkRegion">网络分区:1=中国境内,2=中国境外,3=全球；用于从集群接口筛选并随机选取线路</param>
	/// <returns>0=初始化失败,1=初始化成功</returns>
	ZoneHelper(const  std::string& arg_SoftwareId, const  std::string& arg_soft_ver, const  std::string& arg_EncryptKey, const  std::string& arg_EncryptIv, const eum_EncryptType& arg_encryptType, const eum_LoginType& arg_LoginType, const eum_AgreementType& arg_AgreementType, eum_NetworkRegion arg_NetworkRegion);
	~ZoneHelper();

	/// <summary>返回当前 C++ SDK 版本号（与请求中的 sdk_ver 一致；可在包含本头文件前定义 ZH_SDK_VER_STR 覆盖默认值）。</summary>
	static std::string get_sdk_ver();

	/// <summary>
	/// 查询卡密的状态
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_card"></param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int QueryCard(ApiResponse& out_ApiResponse, const  std::string& arg_card);

	/// <summary>
	/// 解绑卡密
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_card"></param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int UnbindCard(ApiResponse& out_ApiResponse, const  std::string& arg_card);

	/// <summary>
	/// 卡密登录返回心跳所用的Token
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_card">可选-完整卡密</param>
	/// <param name="arg_InvitationCode">邀请码(选填,首次登录的卡密激活)</param>
	/// <param name="arg_VerifyCode">验证码(选填)</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int LoginC(ApiResponse& out_ApiResponse, const std::string& arg_card, std::string arg_InvitationCode = "", std::string arg_VerifyCode = "");
	/// <summary>
	/// 使用卡密给卡密充值
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_card">卡密</param>
	/// <param name="arg_RechargeCard">充值卡</param>
	/// <param name="arg_VerifyCode">验证码(选填)</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int RechargeC(ApiResponse& out_ApiResponse, const std::string& arg_card, const std::string& arg_RechargeCard, std::string arg_VerifyCode = "");
	/// <summary>
	/// 账号查询返回这个账号的信息
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_Account"></param>
	/// <param name="arg_Password"></param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int QueryAccount(ApiResponse& out_ApiResponse, const  std::string& arg_Account, const  std::string& arg_Password);
	/// <summary>
	/// 解绑账号,返回剩余解绑次数以及时间和点数
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_Account"></param>
	/// <param name="arg_Password"></param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int UnbindAccount(ApiResponse& out_ApiResponse, const  std::string& arg_Account, const  std::string& arg_Password);
	/// <summary>
	/// 账号登录返回心跳所用的Token
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_Account">账号</param>
	/// <param name="arg_Password">密码</param>
	/// <param name="arg_VerifyCode">验证码(选填)</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int LoginA(ApiResponse& out_ApiResponse, const std::string& arg_Account, const std::string& arg_Password, std::string arg_VerifyCode = "");
	/// <summary>
	/// 注册并激活卡密的账号
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_Account">账号</param>
	/// <param name="arg_Password">密码</param>
	/// <param name="arg_card">完整卡密</param>
	/// <param name="arg_ContactInfo">联系方式(选填)</param>
	/// <param name="arg_ContactType">联系类型(选填)[1=QQ,2=邮箱,3=手机号,4=微信号]</param>
	/// <param name="arg_InvitationCode">邀请码(选填)</param>
	/// <param name="arg_VerifyCode">验证码(选填)</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int Register(ApiResponse& out_ApiResponse, const std::string& arg_Account, const std::string& arg_Password, const std::string& arg_card = "", std::string arg_ContactInfo = "", eum_ContactType arg_ContactType = eum_ContactType::None, std::string arg_InvitationCode = "", std::string arg_VerifyCode = "");
	/// <summary>
	/// 账号修改密码
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_Account">账号</param>
	/// <param name="arg_NewPassword">新密码</param>
	/// <param name="arg_ContactInfo">联系方式,若注册时没填则填原密码</param>
	/// <param name="arg_ContactType">联系类型(选填)[1=QQ,2=邮箱,3=手机号,4=微信号],若注册时没填则填0</param>
	/// <param name="arg_VerifyCode">验证码(选填)</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int ChangePasswordA(ApiResponse& out_ApiResponse, const std::string& arg_Account, const std::string& arg_NewPassword, std::string arg_ContactInfo = "", eum_ContactType arg_ContactType = eum_ContactType::None, std::string arg_VerifyCode = "");
	/// <summary>
	/// 使用卡密给账号充值
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_Account">账号</param>
	/// <param name="arg_Password">密码</param>
	/// <param name="arg_RechargeCard">充值卡</param>
	/// <param name="arg_VerifyCode">验证码(选填)</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int RechargeA(ApiResponse& out_ApiResponse, const std::string& arg_Account, const std::string& arg_Password, const std::string& arg_RechargeCard, std::string arg_VerifyCode = "");
	/// <summary>
	/// 账号/卡密 的心跳
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int HeartBeat(ApiResponse& out_ApiResponse);
	/// <summary>
	/// 账号/卡密 扣点数
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_score">0=扣点1,整数型,如果是乱七八糟的字符或者<0的 均按照1处理</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int SubScore(ApiResponse& out_ApiResponse, int arg_score);
	/// <summary>
	 /// 获取云变量
	 /// </summary>
	 /// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	 /// <param name="arg_VariableName">云变量Name</param>
	 /// <returns>0=请求失败,1=请求成功</returns>
	int GetAntiVariableValue(ApiResponse& out_ApiResponse, const  std::string& arg_VariableName);
	/// <summary>
	/// 获取云算法
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_AlgorithmName">云算法Name</param>
	/// <param name="arg_ReqArguments">[选填]云算法参数,若为空则自动使用后台设置的参数</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int GetAntiAlgorithmValue(ApiResponse& out_ApiResponse, const  std::string& arg_AlgorithmName, std::string arg_ReqArguments = "");
	/// <summary>
	/// 获取软件信息,用于更新操作,以及获取软件的公告信息
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int GetSoftInfo(ApiResponse& out_ApiResponse);
	/// <summary>
	/// 反馈消息
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_Msg_body"></param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int FeedBack(ApiResponse& out_ApiResponse, const  std::string& arg_Msg_body);
	/// <param name="arg_VerifyCode">验证码(选填)</param>
	int FeedBackWithVerifyCode(ApiResponse& out_ApiResponse, const std::string& arg_Msg_body,
		const std::string& arg_VerifyCode);
	/// <summary>
	/// 日志消息
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_Msg_body"></param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int Log(ApiResponse& out_ApiResponse, const  std::string& arg_Msg_body);
	/// <param name="arg_LogLevel">none/info/debug/warning/error</param>
	/// <param name="arg_CustomType">自定义类型，最多 32 个 UTF-8 字符</param>
	int Log(ApiResponse& out_ApiResponse, const std::string& arg_Msg_body,
		const std::string& arg_LogLevel, const std::string& arg_CustomType = "");
	/// <summary>
	/// 游客(试用)登录返回心跳所用的Token
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_VerifyCode">验证码(选填)</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int LoginT(ApiResponse& out_ApiResponse, std::string arg_VerifyCode = "");
	/// <summary>
	/// 获取客户端配置信息
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int GetClientConfig(ApiResponse& out_ApiResponse);
	/// 获取云文件真实下载地址；requestId 为空时自动生成，传入原值可幂等重试。
	int DownloadCloudFile(ApiResponse& out_ApiResponse, const std::string& fileIdentifier,
		const std::string& version = "", const std::string& requestId = "");
	/// 查询软件历史版本列表。
	int ListVersions(ApiResponse& out_ApiResponse, int page = 1, int pageSize = 20);
	/// 查询当前登录用户自己的反馈消息列表。
	int FeedbackList(ApiResponse& out_ApiResponse, int page = 1, int pageSize = 20);
	/// <summary>
	/// 编辑客户端配置信息
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_Config"></param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int EditClientConfig(ApiResponse& out_ApiResponse, const std::string& arg_Config);
	/// <summary>
	/// 清空客户端配置信息
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int ClearClientConfig(ApiResponse& out_ApiResponse);
	/// <summary>
	/// 获取验证码
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int GetCaptcha(ApiResponse& out_ApiResponse);
	/// <param name="arg_CaptchaScene">验证码场景(选填，消息反馈传 feedback)</param>
	int GetCaptchaWithScene(ApiResponse& out_ApiResponse, const std::string& arg_CaptchaScene);
	/// <summary>
	/// 获取邀请成果
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int GetInviteHarvest(ApiResponse& out_ApiResponse);
	/// <summary>
	/// 获取邀请记录列表
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int GetInviteRecord(ApiResponse& out_ApiResponse);
	/// <summary>
	/// 获取服务器时间
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int GetTimeStamp(ApiResponse& out_ApiResponse);
	/// <summary>
	/// 登出
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int Logout(ApiResponse& out_ApiResponse);
	/// <summary>
	/// 查询在线设备(卡密)
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_card">完整卡密</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int QueryOnlineDeviceC(ApiResponse& out_ApiResponse, const std::string& arg_card);
	/// <summary>
	/// 踢掉在线设备(卡密)
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_card">完整卡密</param>
	/// <param name="arg_index">踢掉索引号,-1代表全踢</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int KickOnlineDeviceC(ApiResponse& out_ApiResponse, const std::string& arg_card, int arg_index);
	/// <summary>
	/// 查询在线设备(账号)
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_Account">账号</param>
	/// <param name="arg_Password">密码</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int QueryOnlineDeviceA(ApiResponse& out_ApiResponse, const std::string& arg_Account, const std::string& arg_Password);
	/// <summary>
	/// 踢掉在线设备(账号)
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_Account">账号</param>
	/// <param name="arg_Password">密码</param>
	/// <param name="arg_index">踢掉索引号,-1代表全踢</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int KickOnlineDeviceA(ApiResponse& out_ApiResponse, const std::string& arg_Account, const std::string& arg_Password, int arg_index);
	/// <summary>
	/// 获取服务器线路
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int GetSvrNodes(ApiResponse& out_ApiResponse);
	/// <summary>
	/// 切换服务器线路
	/// </summary>
	/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
	/// <param name="arg_http_address">完整的http地址</param>
	/// <param name="arg_https_address">完整的https地址</param>
	/// <param name="arg_socket_address">完整的socket地址</param>
	/// <param name="arg_ws_address">完整的ws地址</param>
	/// <param name="arg_wss_address">完整的wss地址</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int ChangeSvrNode(ApiResponse& out_ApiResponse, const std::string& arg_http_address, const std::string& arg_https_address, const std::string& arg_socket_address, const std::string& arg_ws_address, const std::string& arg_wss_address);
	/// <summary>
	/// 发起签到
	/// </summary>
	/// <param name="response"></param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int SignIn(ApiResponse& out_ApiResponse);
	/// <summary>
	/// 发起补签
	/// </summary>
	/// <param name="response"></param>
	/// <param name="arg_TimeStamp_s">补签的时间戳,单位:秒(s)</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int SignInFix(ApiResponse& out_ApiResponse, const std::string& arg_TimeStamp_s);
	/// <summary>
	/// 查询签到历史
	/// </summary>
	/// <param name="response"></param>
	/// <param name="arg_Page">页面,默认:1</param>
	/// <param name="arg_PageSize">页面大小,默认:20</param>
	/// <param name="arg_TimeOrder">顺序,0=最新数据->旧数据,1=旧数据->新数据</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int SignInQueryHistory(ApiResponse& out_ApiResponse, std::string arg_Page = "1", std::string arg_PageSize = "20", std::string arg_TimeOrder = "0");
	/// <summary>
	/// 查询等级列表
	/// </summary>
	/// <param name="response"></param>
	/// <param name="arg_Page">页面,默认:1</param>
	/// <param name="arg_PageSize">页面大小,默认:20</param>
	/// <param name="arg_TimeOrder">顺序,0=最新数据->旧数据,1=旧数据->新数据</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int GradeQueryList(ApiResponse& out_ApiResponse, std::string arg_Page = "1", std::string arg_PageSize = "20", std::string arg_TimeOrder = "0");
	/// <summary>
	/// 查询抽奖列表
	/// </summary>
	/// <param name="response"></param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int LotteryQueryList(ApiResponse& out_ApiResponse);
	/// <summary>
	/// 发起抽奖(包含连抽)
	/// </summary>
	/// <param name="response"></param>
	/// <param name="arg_Num">连抽数量,默认:1</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int LotteryStart(ApiResponse& out_ApiResponse, std::string arg_Num = "1");
	/// <summary>
	/// 查询抽奖历史
	/// </summary>
	/// <param name="response"></param>
	/// <param name="arg_Page">页面,默认:1</param>
	/// <param name="arg_PageSize">页面大小,默认:20</param>
	/// <param name="arg_TimeOrder">顺序,0=最新数据->旧数据,1=旧数据->新数据</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int LotteryQueryHistory(ApiResponse& out_ApiResponse, std::string arg_Page = "1", std::string arg_PageSize = "20", std::string arg_TimeOrder = "0");
	/// <summary>
	/// 查询商城物品列表
	/// </summary>
	/// <param name="response"></param>
	/// <param name="arg_Page">页面,默认:1</param>
	/// <param name="arg_PageSize">页面大小,默认:20</param>
	/// <param name="arg_TimeOrder">顺序,0=最新数据->旧数据,1=旧数据->新数据</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int ShopQueryList(ApiResponse& out_ApiResponse, std::string arg_Page = "1", std::string arg_PageSize = "20", std::string arg_TimeOrder = "0");
	/// <summary>
	/// 购买/兑换物品
	/// </summary>
	/// <param name="response"></param>
	/// <param name="arg_Id"></param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int ShopBuy(ApiResponse& out_ApiResponse, const std::string& arg_Id);
	/// <summary>
	/// 查询购买过的物品记录列表
	/// </summary>
	/// <param name="response"></param>
	/// <param name="arg_Page">页面,默认:1</param>
	/// <param name="arg_PageSize">页面大小,默认:20</param>
	/// <param name="arg_TimeOrder">顺序,0=最新数据->旧数据,1=旧数据->新数据</param>
	/// <returns>0=请求失败,1=请求成功</returns>
	int ShopQueryHistory(ApiResponse& out_ApiResponse, std::string arg_Page = "1", std::string arg_PageSize = "20", std::string arg_TimeOrder = "0");

};
