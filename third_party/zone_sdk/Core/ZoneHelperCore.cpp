#include "ZoneHelperCore.h"
#include "base64.h"
#include "JsonCompat.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>

namespace {

std::string GenerateRequestId() {
	std::random_device source;
	std::uniform_int_distribution<int> byte(0, 255);
	unsigned char value[16];
	for (auto& item : value)
		item = static_cast<unsigned char>(byte(source));
	value[6] = static_cast<unsigned char>((value[6] & 0x0f) | 0x40);
	value[8] = static_cast<unsigned char>((value[8] & 0x3f) | 0x80);
	char text[37];
	std::snprintf(text, sizeof(text),
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
		value[8], value[9], value[10], value[11], value[12], value[13], value[14], value[15]);
	return text;
}

void EncodeMachineNamesForWire(std::string& requestData) {
	auto payload = nlohmann::json::parse(requestData);
	for (const char* field : { "machine_name", "reg_machine_name" }) {
		if (payload.contains(field) && payload[field].is_string())
			payload[field] = "b64:" + base64_encode(payload[field].get<std::string>());
	}
	requestData = payload.dump();
}

bool EndpointMatchesRegion(int net, eum_NetworkRegion region) {
	return net == static_cast<int>(region);
}

void FilterByRegion(const std::vector<ClusterEndpoint>& in, eum_NetworkRegion region, std::vector<ClusterEndpoint>& out) {
	for (const auto& e : in) {
		if (EndpointMatchesRegion(e.net, region))
			out.push_back(e);
	}
}

const ClusterEndpoint* PickRandom(const std::vector<ClusterEndpoint>& pool, std::mt19937& gen) {
	if (pool.empty())
		return nullptr;
	std::uniform_int_distribution<size_t> dist(0, pool.size() - 1);
	return &pool[dist(gen)];
}

std::string EndpointHost(const ClusterEndpoint& e) {
	if (!e.host.empty())
		return e.host;
	return e.ip;
}

std::string MakeHttpOrigin(const std::string& scheme, const ClusterEndpoint& e) {
	const std::string h = EndpointHost(e);
	if (h.empty())
		return {};
	std::string o = scheme + h;
	const int defPort = (scheme == "http://") ? 80 : 443;
	if (e.port > 0 && e.port != defPort)
		o += ":" + std::to_string(e.port);
	return o;
}

std::string MakeWsFullUrl(const std::string& scheme, const ClusterEndpoint& e) {
	const std::string h = EndpointHost(e);
	if (h.empty())
		return {};
	std::string u = scheme + h;
	const int defPort = (scheme == "ws://") ? 80 : 443;
	if (e.port > 0 && e.port != defPort)
		u += ":" + std::to_string(e.port);
	std::string p = e.path.empty() ? "/websocket/api" : e.path;
	if (!p.empty() && p[0] != '/')
		u.push_back('/');
	u += p;
	return u;
}

void ParseClusterArray(const nlohmann::json& data, const char* key, std::vector<ClusterEndpoint>& out) {
	if (!data.contains(key) || !data[key].is_array())
		return;
	for (const auto& el : data[key]) {
		ClusterEndpoint ce;
		ce.name = el.value("name", "");
		ce.ip = el.value("ip", "");
		if (el.contains("port") && el["port"].is_number_integer())
			ce.port = el["port"].get<int>();
		else if (el.contains("port") && el["port"].is_number_unsigned())
			ce.port = static_cast<int>(el["port"].get<unsigned>());
		else
			ce.port = el.value("port", 0);
		ce.host = el.value("host", "");
		ce.path = el.value("path", "");
		ce.net = el.value("net", 0);
		out.push_back(std::move(ce));
	}
}

} // namespace

wrap::Response ZoneHelperCore::SendGetRequestRaw(const std::string& url) {
	return wrap::HttpsRequest(
		wrap::Url{ url },
		wrap::Method{ "GET" },
		wrap::Header{ {"Accept", "application/json"} });
}

void ZoneHelperCore::applyLegacyDefaultEndpoints() {
	svr_zone_path = "/api/zone";
	svr_ws_full_url = "ws://" + svr_wss_Host + "/websocket/api";
	svr_wss_full_url = "wss://" + svr_wss_Host + "/websocket/api";
}

bool ZoneHelperCore::tryApplyClusterEndpoints() {
	std::random_device rd;
	std::mt19937 gen(rd());

	// 集群发现：HTTPS/WSS 优先走 https://；用户协议为 HTTP / SOCKET / WS 或仅需明文拉取时用 http://
	const bool clusterListUsePlainHttp =
		(Z_AgreementType == eum_AgreementType::HTTP ||
		 Z_AgreementType == eum_AgreementType::SOCKET ||
		 Z_AgreementType == eum_AgreementType::WebSocket);

	std::string body;
	if (clusterListUsePlainHttp) {
		body = SendGetRequestRaw("http://api.lzonel.com/api/cluster/list").text;
	}
	else {
		wrap::Response httpsResp = SendGetRequestRaw("https://api.lzonel.com/api/cluster/list");
		body = httpsResp.text;
		if (!httpsResp.err.empty() || httpsResp.status_code != "200" || body.empty())
			body = SendGetRequestRaw("http://api.lzonel.com/api/cluster/list").text;
	}

	nlohmann::json root;
	try {
		root = nlohmann::json::parse(body);
	}
	catch (...) {
		return false;
	}

	int code = -1;
	if (root.contains("code")) {
		if (root["code"].is_number_integer())
			code = root["code"].get<int>();
		else if (root["code"].is_string()) {
			try {
				code = std::stoi(root["code"].get<std::string>());
			}
			catch (...) {
				code = -1;
			}
		}
	}
	if (code != 200 || !root.contains("data") || !root["data"].is_object())
		return false;

	const nlohmann::json& d = root["data"];
	std::vector<ClusterEndpoint> httpE, httpsE, socketE, wsE, wssE;
	ParseClusterArray(d, "http", httpE);
	ParseClusterArray(d, "https", httpsE);
	ParseClusterArray(d, "socket", socketE);
	ParseClusterArray(d, "ws", wsE);
	ParseClusterArray(d, "wss", wssE);

	std::vector<ClusterEndpoint> httpF, httpsF, socketF, wsF, wssF;
	FilterByRegion(httpE, Z_NetworkRegion, httpF);
	FilterByRegion(httpsE, Z_NetworkRegion, httpsF);
	FilterByRegion(socketE, Z_NetworkRegion, socketF);
	FilterByRegion(wsE, Z_NetworkRegion, wsF);
	FilterByRegion(wssE, Z_NetworkRegion, wssF);

	const ClusterEndpoint* ph = PickRandom(httpF, gen);
	const ClusterEndpoint* pss = PickRandom(httpsF, gen);
	const ClusterEndpoint* ps = PickRandom(socketF, gen);
	const ClusterEndpoint* pw = PickRandom(wsF, gen);
	const ClusterEndpoint* pws = PickRandom(wssF, gen);

	bool activeOk = false;
	switch (Z_AgreementType) {
	case eum_AgreementType::HTTP:
		activeOk = ph && !MakeHttpOrigin("http://", *ph).empty();
		break;
	case eum_AgreementType::HTTPS:
		activeOk = pss && !MakeHttpOrigin("https://", *pss).empty();
		break;
	case eum_AgreementType::SOCKET:
		activeOk = ps && !ps->ip.empty() && ps->port > 0;
		break;
	case eum_AgreementType::WebSocket:
		activeOk = pw && !MakeWsFullUrl("ws://", *pw).empty();
		break;
	case eum_AgreementType::WebSockets:
		activeOk = pws && !MakeWsFullUrl("wss://", *pws).empty();
		break;
	default:
		break;
	}
	if (!activeOk)
		return false;

	cluster_http_origin.clear();
	cluster_https_origin.clear();
	if (ph)
		cluster_http_origin = MakeHttpOrigin("http://", *ph);
	if (pss)
		cluster_https_origin = MakeHttpOrigin("https://", *pss);

	if (pss && !pss->path.empty())
		svr_zone_path = pss->path;
	else if (ph && !ph->path.empty())
		svr_zone_path = ph->path;
	else
		svr_zone_path = "/api/zone";

	if (ps) {
		svr_address = ps->ip;
		svr_port = ps->port;
	}
	if (pw)
		svr_ws_full_url = MakeWsFullUrl("ws://", *pw);
	if (pws)
		svr_wss_full_url = MakeWsFullUrl("wss://", *pws);

	return true;
}


ZoneHelperCore::ZoneHelperCore()
{
}
ZoneHelperCore::ZoneHelperCore(const std::string& arg_SoftwareId, const std::string& arg_soft_ver, const std::string& arg_EncryptKey, const std::string& arg_EncryptIv, eum_EncryptType arg_encryptType, eum_LoginType arg_LoginType, eum_AgreementType arg_AgreementType, eum_NetworkRegion arg_NetworkRegion) {

	SoftwareId = arg_SoftwareId;
	soft_ver = arg_soft_ver;
	EncryptKey = arg_EncryptKey;
	EncryptIv = arg_EncryptIv;
	EncryptMode = arg_encryptType;
	Z_LoginType = arg_LoginType;
	Z_AgreementType = arg_AgreementType;
	Z_NetworkRegion = arg_NetworkRegion;

	const bool clusterOk = tryApplyClusterEndpoints();
	if (!clusterOk)
		applyLegacyDefaultEndpoints();

	if (Z_AgreementType == eum_AgreementType::SOCKET) {
		usr_SocketClientCore = new SocketClientCore(svr_address, svr_port, m_SocketReadMsgContainer);
		if (nullptr != usr_SocketClientCore)
		{
			socket_con_status = usr_SocketClientCore->con_status;
		}
	}
	else if (Z_AgreementType == eum_AgreementType::HTTP) {
		if (clusterOk)
			svr_Host = cluster_http_origin;
		else
			svr_Host = "http://" + svr_Host;
		socket_con_status = true;
	}
	else if (Z_AgreementType == eum_AgreementType::HTTPS) {
		if (clusterOk)
			svr_Host = cluster_https_origin;
		else
			svr_Host = "https://" + svr_Host;
		socket_con_status = true;
	}
	else if (Z_AgreementType == eum_AgreementType::WebSocket)
	{
		const std::string wsUrl = clusterOk ? svr_ws_full_url : (std::string("ws://") + svr_wss_Host + "/websocket/api");
		usr_webSocketClient = new  ZoneWebSocketClient(wsUrl);
		if (nullptr != usr_webSocketClient)
		{
			socket_con_status = usr_webSocketClient->con_status;
		}
	}
	else if (Z_AgreementType == eum_AgreementType::WebSockets)
	{
		const std::string wssUrl = clusterOk ? svr_wss_full_url : (std::string("wss://") + svr_wss_Host + "/websocket/api");
		usr_webSocketClient = new ZoneWebSocketClient(wssUrl);
		if (nullptr != usr_webSocketClient)
		{
			socket_con_status = usr_webSocketClient->con_status;
		}
	}
	zoneInit();
}

ZoneHelperCore::~ZoneHelperCore() {
	// Implementation
	if (nullptr != usr_SocketClientCore)
	{
		delete usr_SocketClientCore;
	}
	if (nullptr != usr_webSocketClient)
	{
		delete usr_webSocketClient;
	}
}

bool ZoneHelperCore::QueryCard(const std::string& arg_card, ApiResponse& response) {
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 8);

	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "8" + "\",\n"
		"    \"complete_card\": \"" + arg_card + "\",\n"
		"    \"ip\": \"" + IP + "\",\n"
		"    \"machine_name\": \"" + MachineName + "\",\n"
		"    \"mac_code\": \"" + MacCode + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}

bool ZoneHelperCore::UnbindCard(const std::string& arg_card, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 9);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "9" + "\",\n"
		"    \"complete_card\": \"" + arg_card + "\",\n"
		"    \"ip\": \"" + IP + "\",\n"
		"    \"machine_name\": \"" + MachineName + "\",\n"
		"    \"mac_code\": \"" + MacCode + "\"\n"
		"}";

	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::LoginC(const std::string& arg_card, const std::string& arg_InvitationCode, const std::string& arg_VerifyCode, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 10);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "10" + "\",\n"
		"    \"complete_card\": \"" + arg_card + "\",\n"
		"    \"invitation_code\": \"" + arg_InvitationCode + "\",\n"
		"    \"ip\": \"" + IP + "\",\n"
		"    \"machine_name\": \"" + MachineName + "\",\n"
		"    \"mac_code\": \"" + MacCode + "\",\n"
		"    \"verify_id\": \"" + verifyID + "\",\n"
		"    \"verify_code\": \"" + arg_VerifyCode + "\",\n"
		"    \"fingerprint\": \"" + fingerprint + "\"\n"
		"}";

	if (ToMoreWrite(requestData, time, response))
	{
		this->card_head = arg_card.substr(0, 4);
		this->card = arg_card.substr(4, arg_card.length() - 4);
		this->usr_token = response.Data.Token;
		return true;
	}
	return false;
}

bool ZoneHelperCore::RechargeC(const std::string& arg_card, const std::string& arg_RechargeCard, const std::string& arg_VerifyCode, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 27);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "27" + "\",\n"
		"    \"complete_card\": \"" + arg_card + "\",\n"
		"    \"re_card\": \"" + arg_RechargeCard + "\",\n"
		"    \"ip\": \"" + IP + "\",\n"
		"    \"machine_name\": \"" + MachineName + "\",\n"
		"    \"mac_code\": \"" + MacCode + "\",\n"
		"    \"verify_id\": \"" + verifyID + "\",\n"
		"    \"verify_code\": \"" + arg_VerifyCode + "\",\n"
		"    \"fingerprint\": \"" + fingerprint + "\"\n"
		"}";

	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::QueryAccount(const std::string& arg_Account, const std::string& arg_Password, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 11);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "11" + "\",\n"
		"    \"account\": \"" + arg_Account + "\",\n"
		"    \"password\": \"" + arg_Password + "\",\n"
		"    \"ip\": \"" + IP + "\",\n"
		"    \"machine_name\": \"" + MachineName + "\",\n"
		"    \"mac_code\": \"" + MacCode + "\"\n"
		"}";

	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::UnbindAccount(const std::string& arg_Account, const std::string& arg_Password, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 12);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "12" + "\",\n"
		"    \"account\": \"" + arg_Account + "\",\n"
		"    \"password\": \"" + arg_Password + "\",\n"
		"    \"ip\": \"" + IP + "\",\n"
		"    \"machine_name\": \"" + MachineName + "\",\n"
		"    \"mac_code\": \"" + MacCode + "\"\n"
		"}";

	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::LoginA(const std::string& arg_Account, const std::string& arg_Password, const std::string& arg_VerifyCode, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 14);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "14" + "\",\n"
		"    \"account\": \"" + arg_Account + "\",\n"
		"    \"password\": \"" + arg_Password + "\",\n"
		"    \"ip\": \"" + IP + "\",\n"
		"    \"machine_name\": \"" + MachineName + "\",\n"
		"    \"mac_code\": \"" + MacCode + "\",\n"
		"    \"verify_id\": \"" + verifyID + "\",\n"
		"    \"verify_code\": \"" + arg_VerifyCode + "\",\n"
		"    \"fingerprint\": \"" + fingerprint + "\"\n"
		"}";

	if (ToMoreWrite(requestData, time, response))
	{
		this->account = arg_Account;
		this->password = arg_Password;
		this->usr_token = response.Data.Token;
		return true;
	}
	return false;
}
bool ZoneHelperCore::Register(const std::string& arg_Account, const std::string& arg_Password, const std::string& arg_Card, const std::string& arg_ContactInfo, const eum_ContactType& arg_ContactType, const std::string& arg_InvitationCode, const std::string& arg_VerifyCode, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 13);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "13" + "\",\n"
		"    \"reg_account\": \"" + arg_Account + "\",\n"
		"    \"reg_password\": \"" + arg_Password + "\",\n"
		"    \"reg_contact_info\": \"" + arg_ContactInfo + "\",\n"
		"    \"reg_contact_type\": \"" + std::to_string((int)arg_ContactType) + "\",\n"
		"    \"reg_invitation_code\": \"" + arg_InvitationCode + "\",\n"
		"    \"reg_card\": \"" + arg_Card + "\",\n"
		"    \"reg_ip\": \"" + IP + "\",\n"
		"    \"reg_machine_name\": \"" + MachineName + "\",\n"
		"    \"mac_code\": \"" + MacCode + "\",\n"
		"    \"verify_id\": \"" + verifyID + "\",\n"
		"    \"verify_code\": \"" + arg_VerifyCode + "\",\n"
		"    \"fingerprint\": \"" + fingerprint + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}

bool ZoneHelperCore::ChangePasswordA(const std::string& arg_Account, const std::string& arg_NewPassword, const std::string& arg_ContactInfo, const eum_ContactType& arg_ContactType, const std::string& arg_VerifyCode, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 22);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "22" + "\",\n"
		"    \"account\": \"" + arg_Account + "\",\n"
		"    \"password\": \"" + arg_NewPassword + "\",\n"
		"    \"contact_info\": \"" + arg_ContactInfo + "\",\n"
		"    \"contact_type\": \"" + std::to_string((int)arg_ContactType) + "\",\n"
		"    \"ip\": \"" + IP + "\",\n"
		"    \"machine_name\": \"" + MachineName + "\",\n"
		"    \"mac_code\": \"" + MacCode + "\",\n"
		"    \"verify_id\": \"" + verifyID + "\",\n"
		"    \"verify_code\": \"" + arg_VerifyCode + "\",\n"
		"    \"fingerprint\": \"" + fingerprint + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}

bool ZoneHelperCore::RechargeA(const std::string& arg_Account, const std::string& arg_Password, const std::string& arg_RechargeCard, const std::string& arg_VerifyCode, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 23);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "23" + "\",\n"
		"    \"account\": \"" + arg_Account + "\",\n"
		"    \"password\": \"" + arg_Password + "\",\n"
		"    \"re_card\": \"" + arg_RechargeCard + "\",\n"
		"    \"ip\": \"" + IP + "\",\n"
		"    \"machine_name\": \"" + MachineName + "\",\n"
		"    \"mac_code\": \"" + MacCode + "\",\n"
		"    \"verify_id\": \"" + verifyID + "\",\n"
		"    \"verify_code\": \"" + arg_VerifyCode + "\",\n"
		"    \"fingerprint\": \"" + fingerprint + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}

bool ZoneHelperCore::HeartBeat(ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);

	int tmp_mode = 1;
	if (1 == this->on_TryMode)
	{
		//试用模式
		tmp_mode = 17;
	}

	int post_meth = CalcPostMethod(time_l, tmp_mode);

	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + std::to_string(tmp_mode) + "\",\n"
		"    \"ip\": \"" + IP + "\",\n"
		"    \"machine_name\": \"" + MachineName + "\",\n"
		"    \"mac_code\": \"" + MacCode + "\",\n"
		"    \"fingerprint\": \"" + fingerprint + "\",\n"
		"    \"token\": \"" + usr_token + "\"\n"
		"}";

	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::SubScore(int arg_score, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);

	int tmp_mode = 2;
	if (1 == this->on_TryMode)
	{
		//试用模式
		tmp_mode = 18;
	}

	int post_meth = CalcPostMethod(time_l, tmp_mode);

	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + std::to_string(tmp_mode) + "\",\n"
		"    \"score\": " + std::to_string(arg_score) + ",\n"
		"    \"token\": \"" + usr_token + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);

}
bool ZoneHelperCore::GetAntiVariableValue(const std::string& arg_VariableName, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 3);

	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "3" + "\",\n"
		"    \"variable_name\": \"" + arg_VariableName + "\",\n"
		"    \"token\": \"" + usr_token + "\"\n"
		"}";

	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::GetAntiAlgorithmValue(const std::string& arg_AlgorithmName, const std::string& arg_ReqArguments, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 4);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "4" + "\",\n"
		"    \"algorithm_name\": \"" + arg_AlgorithmName + "\",\n"
		"    \"req_arguments\": \"" + escapeJSONSpecialChars(arg_ReqArguments) + "\",\n"
		"    \"token\": \"" + usr_token + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::GetSoftInfo(ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 0);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "0" + "\",\n"
		"    \"ip\": \"" + IP + "\",\n"
		"    \"machine_name\": \"" + MachineName + "\",\n"
		"    \"mac_code\": \"" + MacCode + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}

bool ZoneHelperCore::GetConfig(ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 19);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "19" + "\",\n"
		"    \"token\": \"" + usr_token + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}

bool ZoneHelperCore::DownloadCloudFile(const std::string& fileIdentifier, const std::string& version,
	const std::string& requestId, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 49);
	nlohmann::json request = {
		{ "method", std::to_string(post_meth) }, { "i", "49" },
		{ "file_identifier", fileIdentifier }, { "version", version },
		{ "request_id", requestId.empty() ? GenerateRequestId() : requestId },
		{ "device_id", MacCode }, { "token", usr_token }
	};
	return ToMoreWrite(request.dump(), time, response);
}

bool ZoneHelperCore::ListVersions(int page, int pageSize, ApiResponse& response)
{
	page = (std::max)(1, (std::min)(10000, page));
	pageSize = (std::max)(1, (std::min)(200, pageSize));
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 50);
	nlohmann::json request = {
		{ "method", std::to_string(post_meth) }, { "i", "50" },
		{ "page", page }, { "page_size", pageSize }
	};
	return ToMoreWrite(request.dump(), time, response);
}

bool ZoneHelperCore::FeedbackList(int page, int pageSize, ApiResponse& response)
{
	page = (std::max)(1, (std::min)(10000, page));
	pageSize = (std::max)(1, (std::min)(200, pageSize));
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 51);
	nlohmann::json request = {
		{ "method", std::to_string(post_meth) }, { "i", "51" }, { "token", usr_token },
		{ "page", page }, { "page_size", pageSize }
	};
	return ToMoreWrite(request.dump(), time, response);
}
bool ZoneHelperCore::EditConfig(const std::string& arg_Config, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 20);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "20" + "\",\n"
		"    \"token\": \"" + usr_token + "\",\n"
		"    \"cfg_data\": \"" + arg_Config + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::ClearConfig(ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 21);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "21" + "\",\n"
		"    \"token\": \"" + usr_token + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::GetVerifyCode(ApiResponse& response)
{
	return GetVerifyCodeWithScene("", response);
}

bool ZoneHelperCore::GetVerifyCodeWithScene(const std::string& arg_CaptchaScene, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 24);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "24" + "\",\n"
		"    \"captcha_scene\": \"" + arg_CaptchaScene + "\"\n"
		"}";

	if (ToMoreWrite(requestData, time, response))
	{
		verifyID = response.Data.VerifyID;
	}
	return "" != verifyID;
}

bool ZoneHelperCore::GetInviteHarvest(ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 25);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "25" + "\",\n"
		"    \"token\": \"" + usr_token + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}

bool ZoneHelperCore::GetInviteRecord(ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 26);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "26" + "\",\n"
		"    \"token\": \"" + usr_token + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::GetTimeStamp(ApiResponse& response)
{
	//std::string time = GetLocalTimestamp();
	//long long time_l = std::stoll(time);
	//int post_meth = CalcPostMethod(time_l, 28);
	std::string time = "";
	int post_meth = 28;
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + std::to_string(post_meth) + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}

bool ZoneHelperCore::Logout(ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 29);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "29" + "\",\n"
		"    \"token\": \"" + usr_token + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::QueryOnlineDeviceC(const std::string& arg_card, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 30);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "30" + "\",\n"
		"    \"complete_card\": \"" + arg_card + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::KickOnlineDeviceC(const std::string& arg_card, int arg_index, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 31);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "31" + "\",\n"
		"    \"complete_card\": \"" + arg_card + "\",\n"
		"    \"kick_index\": \"" + std::to_string(arg_index) + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::QueryOnlineDeviceA(const std::string& arg_Account, const std::string& arg_Password, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 32);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "32" + "\",\n"
		"    \"account\": \"" + arg_Account + "\",\n"
		"    \"password\": \"" + arg_Password + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::KickOnlineDeviceA(const std::string& arg_Account, const std::string& arg_Password, int arg_index, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 33);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "33" + "\",\n"
		"    \"account\": \"" + arg_Account + "\",\n"
		"    \"password\": \"" + arg_Password + "\",\n"
		"    \"kick_index\": \"" + std::to_string(arg_index) + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::GetSvrNodes(ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 34);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "34" + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
void ZoneHelperCore::extractIpAndPort(const std::string& input) {
	// Regular expression to match tcp:// followed by IP and port
	std::regex pattern(R"(^tcp://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):(\d+)$)");
	std::smatch match;

	if (std::regex_match(input, match, pattern)) {
		this->svr_address = match[1].str();  // Extracted IP
		this->svr_port = std::stoi(match[2].str());  // Extracted port
		// return {svr_address, svr_port};
	}
	else {
		throw std::invalid_argument("Invalid format");
	}
}
bool ZoneHelperCore::ChangeSvrNode(const std::string& arg_http_address, const std::string& arg_https_address, const std::string& arg_socket_address, const std::string& arg_ws_address, const std::string& arg_wss_address, ApiResponse& response)
{
	try
	{
		if (this->Z_AgreementType == eum_AgreementType::SOCKET)
		{
			extractIpAndPort(arg_socket_address);
			if (nullptr != usr_SocketClientCore)
			{
				delete usr_SocketClientCore;
			}
			usr_SocketClientCore = new SocketClientCore(svr_address, svr_port, m_SocketReadMsgContainer);
			if (nullptr != usr_SocketClientCore)
			{
				socket_con_status = usr_SocketClientCore->con_status;
			}

		}
		else if (this->Z_AgreementType == eum_AgreementType::HTTP)
		{
			this->svr_Host = arg_http_address;
			this->socket_con_status = true;
		}
		else if (this->Z_AgreementType == eum_AgreementType::HTTPS)
		{
			this->svr_Host = arg_https_address;
			this->socket_con_status = true;
		}
		else if (Z_AgreementType == eum_AgreementType::WebSocket)
		{
			if (nullptr != usr_webSocketClient)
			{
				delete usr_webSocketClient;
			}
			usr_webSocketClient = new  ZoneWebSocketClient(arg_ws_address);
			if (nullptr != usr_webSocketClient)
			{
				socket_con_status = usr_webSocketClient->con_status;
			}
		}
		else if (Z_AgreementType == eum_AgreementType::WebSockets)
		{
			if (nullptr != usr_webSocketClient)
			{
				delete usr_webSocketClient;
			}
			usr_webSocketClient = new ZoneWebSocketClient(arg_wss_address);
			if (nullptr != usr_webSocketClient)
			{
				socket_con_status = usr_webSocketClient->con_status;
			}
		}
	}
	catch (const std::exception&)
	{

		return false;
	}
	return true;
}

bool ZoneHelperCore::SendMessageZ(int arg_Msg_type, const std::string& arg_Msg_body,
	ApiResponse& response)
{
	return SendMessageZWithVerifyCode(arg_Msg_type, arg_Msg_body, "", response);
}

bool ZoneHelperCore::SendMessageZWithVerifyCode(int arg_Msg_type, const std::string& arg_Msg_body,
	const std::string& arg_VerifyCode, ApiResponse& response,
	const std::string& arg_LogLevel, const std::string& arg_CustomType)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, arg_Msg_type + 4);

	std::string A = "";
	std::string B = "";
	if (eum_LoginType::Account == this->Z_LoginType)
	{
		//apiUrl = svr_Host + "/api/account/sendmsg";
		A = this->account;
		B = this->password;
	}
	else if (eum_LoginType::Card == this->Z_LoginType)
	{
		//apiUrl = svr_Host + "/api/card/sendmsg";
		A = this->card_head;
		B = this->card;
	}


	if (arg_Msg_type == 2)
	{
		std::string requestData = "{\n"
			"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
			"    \"i\": \"" + std::to_string(arg_Msg_type + 4) + "\",\n"
			"    \"msg_type\": \"" + std::to_string(arg_Msg_type) + "\",\n"
			"    \"msg_body\": \"" + arg_Msg_body + "\",\n"
			"    \"a\": \"" + A + "\",\n"
			"    \"b\": \"" + B + "\",\n"
			"    \"token\": \"" + usr_token + "\",\n"
			"    \"ip\": \"" + IP + "\",\n"
			"    \"machine_name\": \"" + MachineName + "\",\n"
			"    \"mac_code\": \"" + MacCode + "\",\n"
			"    \"verify_id\": \"" + verifyID + "\",\n"
			"    \"verify_code\": \"" + arg_VerifyCode + "\",\n"
			"    \"fingerprint\": \"" + fingerprint + "\"\n}";
		return ToMoreWrite(requestData, time, response);
	}
	if (arg_Msg_type != 3)
	{
		std::string requestData = "{\n"
			"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
			"    \"i\": \"" + std::to_string(arg_Msg_type + 4) + "\",\n"
			"    \"msg_type\": \"" + std::to_string(arg_Msg_type) + "\",\n"
			"    \"msg_body\": \"" + arg_Msg_body + "\",\n"
			"    \"a\": \"" + A + "\",\n"
			"    \"b\": \"" + B + "\",\n"
			"    \"token\": \"" + usr_token + "\",\n"
			"    \"ip\": \"" + IP + "\",\n"
			"    \"machine_name\": \"" + MachineName + "\",\n"
			"    \"mac_code\": \"" + MacCode + "\"\n}";
		return ToMoreWrite(requestData, time, response);
	}
	nlohmann::json request = {
		{ "method", std::to_string(post_meth) }, { "i", "7" }, { "msg_type", "3" },
		{ "msg_body", arg_Msg_body }, { "a", A }, { "b", B }, { "token", usr_token },
		{ "ip", IP }, { "machine_name", MachineName }, { "mac_code", MacCode },
		{ "log_level", arg_LogLevel.empty() ? "none" : arg_LogLevel },
		{ "custom_type", arg_CustomType }
	};
	return ToMoreWrite(request.dump(), time, response);

}
bool ZoneHelperCore::FeedBack(const std::string& arg_Msg_body, ApiResponse& response)
{
	return FeedBackWithVerifyCode(arg_Msg_body, "", response);
}
bool ZoneHelperCore::FeedBackWithVerifyCode(const std::string& arg_Msg_body,
	const std::string& arg_VerifyCode, ApiResponse& response)
{
	return SendMessageZWithVerifyCode(2, arg_Msg_body, arg_VerifyCode, response);
}
bool ZoneHelperCore::Log(const std::string& arg_Msg_body, ApiResponse& response)
{
	return Log(arg_Msg_body, "none", "", response);
}
bool ZoneHelperCore::Log(const std::string& arg_Msg_body, const std::string& arg_LogLevel,
	const std::string& arg_CustomType, ApiResponse& response)
{
	return SendMessageZWithVerifyCode(3, arg_Msg_body, "", response, arg_LogLevel, arg_CustomType);
}

bool ZoneHelperCore::TryIt(const std::string& arg_VerifyCode, ApiResponse& response)
{

	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 16);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "16" + "\",\n"
		"    \"ip\": \"" + IP + "\",\n"
		"    \"machine_name\": \"" + MachineName + "\",\n"
		"    \"mac_code\": \"" + MacCode + "\",\n"
		"    \"verify_id\": \"" + verifyID + "\",\n"
		"    \"verify_code\": \"" + arg_VerifyCode + "\",\n"
		"    \"fingerprint\": \"" + fingerprint + "\"\n"
		"}";

	if (ToMoreWrite(requestData, time, response))
	{
		this->on_TryMode = 1;
		this->usr_token = response.Data.Token;
		return true;
	}
	return false;

}
bool ZoneHelperCore::SignIn(ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 35);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "35" + "\",\n"
		"    \"token\": \"" + this->usr_token + "\",\n"
		"    \"ip\": \"" + this->IP + "\",\n"
		"    \"machine_name\": \"" + this->MachineName + "\",\n"
		"    \"mac_code\": \"" + this->MacCode + "\",\n"
		"    \"fingerprint\": \"" + this->fingerprint + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::SignInFix(const std::string& arg_TimeStamp_s, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 36);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "36" + "\",\n"
		"    \"fix_time\": \"" + arg_TimeStamp_s + "\",\n"
		"    \"token\": \"" + this->usr_token + "\",\n"
		"    \"ip\": \"" + this->IP + "\",\n"
		"    \"machine_name\": \"" + this->MachineName + "\",\n"
		"    \"mac_code\": \"" + this->MacCode + "\",\n"
		"    \"fingerprint\": \"" + this->fingerprint + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::SignInQueryHistory(const string& arg_Page, const string& arg_PageSize, const string& arg_TimeOrder, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 37);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "37" + "\",\n"
		"    \"page\": \"" + arg_Page + "\",\n"
		"    \"page_size\": \"" + arg_PageSize + "\",\n"
		"    \"t_order\": \"" + arg_TimeOrder + "\",\n"
		"    \"token\": \"" + this->usr_token + "\",\n"
		"    \"ip\": \"" + this->IP + "\",\n"
		"    \"machine_name\": \"" + this->MachineName + "\",\n"
		"    \"mac_code\": \"" + this->MacCode + "\",\n"
		"    \"fingerprint\": \"" + this->fingerprint + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::GradeQueryList(const string& arg_Page, const string& arg_PageSize, const string& arg_TimeOrder, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 38);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "38" + "\",\n"
		"    \"page\": \"" + arg_Page + "\",\n"
		"    \"page_size\": \"" + arg_PageSize + "\",\n"
		"    \"t_order\": \"" + arg_TimeOrder + "\",\n"
		"    \"token\": \"" + this->usr_token + "\",\n"
		"    \"ip\": \"" + this->IP + "\",\n"
		"    \"machine_name\": \"" + this->MachineName + "\",\n"
		"    \"mac_code\": \"" + this->MacCode + "\",\n"
		"    \"fingerprint\": \"" + this->fingerprint + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::LotteryQueryList(ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 39);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "39" + "\",\n"
		"    \"token\": \"" + this->usr_token + "\",\n"
		"    \"ip\": \"" + this->IP + "\",\n"
		"    \"machine_name\": \"" + this->MachineName + "\",\n"
		"    \"mac_code\": \"" + this->MacCode + "\",\n"
		"    \"fingerprint\": \"" + this->fingerprint + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::LotteryStart(const std::string& arg_Num, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 40);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "40" + "\",\n"
		"    \"num\": \"" + arg_Num + "\",\n"
		"    \"token\": \"" + this->usr_token + "\",\n"
		"    \"ip\": \"" + this->IP + "\",\n"
		"    \"machine_name\": \"" + this->MachineName + "\",\n"
		"    \"mac_code\": \"" + this->MacCode + "\",\n"
		"    \"fingerprint\": \"" + this->fingerprint + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::LotteryQueryHistory(const std::string& arg_Page, const std::string& arg_PageSize, const std::string& arg_TimeOrder, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 41);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "41" + "\",\n"
		"    \"page\": \"" + arg_Page + "\",\n"
		"    \"page_size\": \"" + arg_PageSize + "\",\n"
		"    \"t_order\": \"" + arg_TimeOrder + "\",\n"
		"    \"token\": \"" + this->usr_token + "\",\n"
		"    \"ip\": \"" + this->IP + "\",\n"
		"    \"machine_name\": \"" + this->MachineName + "\",\n"
		"    \"mac_code\": \"" + this->MacCode + "\",\n"
		"    \"fingerprint\": \"" + this->fingerprint + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::ShopQueryList(const std::string& arg_Page, const std::string& arg_PageSize, const std::string& arg_TimeOrder, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 42);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "42" + "\",\n"
		"    \"page\": \"" + arg_Page + "\",\n"
		"    \"page_size\": \"" + arg_PageSize + "\",\n"
		"    \"t_order\": \"" + arg_TimeOrder + "\",\n"
		"    \"token\": \"" + this->usr_token + "\",\n"
		"    \"ip\": \"" + this->IP + "\",\n"
		"    \"machine_name\": \"" + this->MachineName + "\",\n"
		"    \"mac_code\": \"" + this->MacCode + "\",\n"
		"    \"fingerprint\": \"" + this->fingerprint + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::ShopBuy(const std::string& arg_Id, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 43);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "43" + "\",\n"
		"    \"id\": \"" + arg_Id + "\",\n"
		"    \"token\": \"" + this->usr_token + "\",\n"
		"    \"ip\": \"" + this->IP + "\",\n"
		"    \"machine_name\": \"" + this->MachineName + "\",\n"
		"    \"mac_code\": \"" + this->MacCode + "\",\n"
		"    \"fingerprint\": \"" + this->fingerprint + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}
bool ZoneHelperCore::ShopQueryHistory(const std::string& arg_Page, const std::string& arg_PageSize, const std::string& arg_TimeOrder, ApiResponse& response)
{
	std::string time = GetLocalTimestamp();
	long long time_l = std::stoll(time);
	int post_meth = CalcPostMethod(time_l, 44);
	std::string requestData = "{\n"
		"    \"method\": \"" + std::to_string(post_meth) + "\",\n"
		"    \"i\": \"" + "44" + "\",\n"
		"    \"page\": \"" + arg_Page + "\",\n"
		"    \"page_size\": \"" + arg_PageSize + "\",\n"
		"    \"t_order\": \"" + arg_TimeOrder + "\",\n"
		"    \"token\": \"" + this->usr_token + "\",\n"
		"    \"ip\": \"" + this->IP + "\",\n"
		"    \"machine_name\": \"" + this->MachineName + "\",\n"
		"    \"mac_code\": \"" + this->MacCode + "\",\n"
		"    \"fingerprint\": \"" + this->fingerprint + "\"\n"
		"}";


	return ToMoreWrite(requestData, time, response);
}

bool ZoneHelperCore::DeserializeJson(const std::string& de_data, ApiResponse& response) {
	try {
		//std::cout << "raw_data[" << de_data << "]" << std::endl;
		if ("" == de_data)
		{

			return false;
		}
		// Step 1: Parse the JSON string
		nlohmann::json jsonData = nlohmann::json::parse(de_data);
		if (!jsonData.is_object())
			return false;

		// Step 2: Parse top-level ApiResponse fields
		response.Status = zh_json_compat::String(jsonData, "status");
		response.Message = zh_json_compat::String(jsonData, "message");
		response.Code = zh_json_compat::String(jsonData, "code");
		response.Soft_encrypt_data = zh_json_compat::String(jsonData, "soft_encrypt_data");
		response.Soft_id = zh_json_compat::String(jsonData, "soft_id");
		response.Time = zh_json_compat::String(jsonData, "time");
		response.Sign = zh_json_compat::String(jsonData, "sign");

		// Step 3: Early return if soft_encrypt_data is not empty and run_status is empty
		if (!response.Soft_encrypt_data.empty() && response.Data.Run_status.empty()) {
			return true;
		}

		// Step 4: Parse the "data" section
		if (jsonData.contains("data") && !jsonData["data"].is_null()) {
			const nlohmann::json& dataJson = jsonData["data"];
			response.Data.RawJson = dataJson.dump();
			if (!dataJson.is_object())
				return true;
			response.Data.DownloadUrl = zh_json_compat::String(dataJson, "download_url");
			response.Data.AuthorizationId = zh_json_compat::String(dataJson, "authorization_id");
			response.Data.FileId = zh_json_compat::String(dataJson, "file_id");
			response.Data.VersionId = zh_json_compat::String(dataJson, "version_id");
			response.Data.Version = zh_json_compat::String(dataJson, "version");
			response.Data.FileName = zh_json_compat::String(dataJson, "file_name");
			response.Data.SizeBytes = zh_json_compat::Int64(dataJson, "size_bytes");
			response.Data.Md5 = zh_json_compat::String(dataJson, "md5");
			response.Data.Sha256 = zh_json_compat::String(dataJson, "sha256");
			response.Data.ContentType = zh_json_compat::String(dataJson, "content_type");
			response.Data.DeliveryChannel = zh_json_compat::String(dataJson, "delivery_channel");
			response.Data.BillingRegion = zh_json_compat::String(dataJson, "billing_region");
			response.Data.ChargedTrafficBytes = zh_json_compat::Int64(dataJson, "charged_traffic_bytes");
			response.Data.ExpiresAtUnix = zh_json_compat::Int64(dataJson, "expires_at_unix");
			response.Data.HasChargedAgain = zh_json_compat::TryBool(dataJson, "charged_again", response.Data.ChargedAgain);
			response.Data.RowCount = zh_json_compat::Int64(dataJson, "row_count");
			response.Data.Page = zh_json_compat::Int(dataJson, "page");
			response.Data.PageSize = zh_json_compat::Int(dataJson, "page_size");
			response.Data.HasMore = zh_json_compat::Bool(dataJson, "has_more");
			response.Data.VersionsJson = zh_json_compat::ArrayOrEmpty(dataJson, "data");
			response.Data.FeedbackItemsJson = zh_json_compat::ArrayOrEmpty(dataJson, "items");

			// Macro to simplify value extraction with default empty string
#define SAFE_ASSIGN(field, jsonKey) \
                response.Data.field = zh_json_compat::String(dataJson, jsonKey)

			// Assign string fields
			SAFE_ASSIGN(Token, "Token");
			SAFE_ASSIGN(ExpirationTime, "Expiration_time");
			SAFE_ASSIGN(ExpirationNum, "Expiration_num");
			SAFE_ASSIGN(ExpirationTimeHeartBeat, "Expiration_time_HeartBeat");
			SAFE_ASSIGN(Message, "Message");
			SAFE_ASSIGN(Message2, "message");
			SAFE_ASSIGN(Title, "Title");
			SAFE_ASSIGN(value, "value");
			SAFE_ASSIGN(Status, "Status");
			SAFE_ASSIGN(Run_status, "run_status");
			SAFE_ASSIGN(New_version, "New_version");
			SAFE_ASSIGN(New_notice, "New_notice");
			SAFE_ASSIGN(New_downloadurl, "New_downloadurl");
			SAFE_ASSIGN(New_downloadpwd, "New_downloadpwd");
			SAFE_ASSIGN(SoftwareName, "SoftwareName");
			SAFE_ASSIGN(SoftwareVer, "SoftwareVer");
			SAFE_ASSIGN(LoginType, "LoginType");
			SAFE_ASSIGN(Probation, "Probation");
			SAFE_ASSIGN(InvitationMode, "InvitationMode");
			SAFE_ASSIGN(VerifyMode, "VerifyMode");
			SAFE_ASSIGN(Notice, "Notice");
			SAFE_ASSIGN(Account, "Account");
			SAFE_ASSIGN(Password, "Password");
			SAFE_ASSIGN(CardHead, "CardHead");
			SAFE_ASSIGN(Card, "Card");
			SAFE_ASSIGN(CapacityForTime, "CapacityForTime");
			SAFE_ASSIGN(CapacityForNum, "CapacityForNum");
			SAFE_ASSIGN(Use_time, "Use_time");
			SAFE_ASSIGN(UsedMacCode, "UsedMacCode");
			SAFE_ASSIGN(UsedIp, "UsedIp");
			SAFE_ASSIGN(UsedMachineName, "UsedMachineName");
			SAFE_ASSIGN(UsedMacCodeList, "UsedMacCodeList");
			SAFE_ASSIGN(UsedIpList, "UsedIpList");
			SAFE_ASSIGN(Use_timeList, "Use_timeList");
			SAFE_ASSIGN(UsedMachineNameList, "UsedMachineNameList");
			SAFE_ASSIGN(Unbind, "Unbind");
			SAFE_ASSIGN(PriceName, "PriceName");
			SAFE_ASSIGN(PriceTypeStr, "PriceTypeStr");
			SAFE_ASSIGN(PriceType, "PriceType");
			SAFE_ASSIGN(PriceNum, "PriceNum");
			SAFE_ASSIGN(PriceUnbind, "PriceUnbind");
			SAFE_ASSIGN(ClientCfgId, "ClientCfgId");
			SAFE_ASSIGN(ClientInvitationCode, "ClientInvitationCode");
			SAFE_ASSIGN(ClientInvitationCodeB, "ClientInvitationCodeB");
			SAFE_ASSIGN(RefillCardList, "RefillCardList");
			SAFE_ASSIGN(VerifyID, "verify_id");
			SAFE_ASSIGN(VerifyData, "verify_data");
			SAFE_ASSIGN(InvitationCode, "invitation_code");
			SAFE_ASSIGN(Harvest, "harvest");
			SAFE_ASSIGN(Inv_count, "inv_count");
			SAFE_ASSIGN(Timestamp, "timestamp");
			SAFE_ASSIGN(Timestamp_ms, "timestamp_ms");
			SAFE_ASSIGN(Datetime_1, "datetime_1");
			SAFE_ASSIGN(Datetime_2, "datetime_2");
			SAFE_ASSIGN(Week_1, "week_1");
			SAFE_ASSIGN(Week_2, "week_2");
			SAFE_ASSIGN(Week_3, "week_3");
			SAFE_ASSIGN(Week_4, "week_4");

			SAFE_ASSIGN(OldDevice, "OldDevice");
			SAFE_ASSIGN(AutoUbndDeT, "AutoUbndDeT");
			SAFE_ASSIGN(AutoUbndDeS, "AutoUbndDeS");
			SAFE_ASSIGN(UnBind, "UnBind");
			SAFE_ASSIGN(LoginStatus, "LoginStatus");
			SAFE_ASSIGN(FirstLogin, "FirstLogin");
			SAFE_ASSIGN(AutoExUbnd, "AutoExUbnd");
			SAFE_ASSIGN(OnlineCount, "OnlineCount");
			SAFE_ASSIGN(FirstRewardScore, "FirstRewardScore");
			SAFE_ASSIGN(FirstRewardTime, "FirstRewardTime");
			SAFE_ASSIGN(RegRewardScore, "RegRewardScore");
			SAFE_ASSIGN(RegRewardTime, "RegRewardTime");
			SAFE_ASSIGN(RegStatus, "RegStatus");
			SAFE_ASSIGN(UbndDeT, "UbndDeT");
			SAFE_ASSIGN(UbndDeS, "UbndDeS");
			SAFE_ASSIGN(UnBindStatus, "UnBindStatus");
			SAFE_ASSIGN(SubNum, "SubNum");
			SAFE_ASSIGN(SubSs, "SubSs");
			SAFE_ASSIGN(OnlineUser, "OnlineUser");
			SAFE_ASSIGN(OnlineUserMult, "OnlineUserMult");
			SAFE_ASSIGN(OnlineTourist, "OnlineTourist");
			SAFE_ASSIGN(OnlineTouristMult, "OnlineTouristMult");
			SAFE_ASSIGN(VerStatus, "VerStatus");
			SAFE_ASSIGN(RechargeStatus, "RechargeStatus");
			SAFE_ASSIGN(HbStatus, "HbStatus");
			SAFE_ASSIGN(CloudeLastTimeRead, "CloudeLastTimeRead");
			SAFE_ASSIGN(CloudeLastTimeWrite, "CloudeLastTimeWrite");
			SAFE_ASSIGN(CloudeCountRead, "CloudeCountRead");
			SAFE_ASSIGN(CloudeCountWrite, "CloudeCountWrite");
			SAFE_ASSIGN(ExStatus, "ExStatus");
			SAFE_ASSIGN(ExLogout, "ExLogout");
			SAFE_ASSIGN(ExOnlineDev, "ExOnlineDev");
			//SAFE_ASSIGN(online_client, "online_client");
			SAFE_ASSIGN(kick_record, "kick_record");


			// Remove macro to prevent accidental reuse
#undef SAFE_ASSIGN

// Handle numeric fields
			if (dataJson.contains("Current_Score")) {
				response.Data.Current_Score = static_cast<long>(zh_json_compat::Int(dataJson, "Current_Score"));
			}

			// Parse InvitationSubData
			if (dataJson.contains("sub_data") && dataJson["sub_data"].is_array()) {
				response.Data.InvitationSubData.clear(); // Clear existing data
				for (const auto& subDataJson : dataJson["sub_data"]) {
					InvSubData invSubData;
					invSubData.Nickname = zh_json_compat::String(subDataJson, "Nickname");
					invSubData.InvitedCode_1 = zh_json_compat::String(subDataJson, "InvitedCode_1");
					invSubData.InvitedCode_2 = zh_json_compat::String(subDataJson, "InvitedCode_2");
					invSubData.SoftwarePriceId = zh_json_compat::String(subDataJson, "SoftwarePriceId");
					invSubData.CommissionData = zh_json_compat::String(subDataJson, "CommissionData");
					invSubData.CommissionType = zh_json_compat::String(subDataJson, "CommissionType");
					invSubData.Creat_time = zh_json_compat::String(subDataJson, "Creat_time");
					invSubData.ChangeType_s = zh_json_compat::String(subDataJson, "ChangeType_s");
					invSubData.ChangeType = zh_json_compat::String(subDataJson, "ChangeType");
					invSubData.Notes = zh_json_compat::String(subDataJson, "Notes");

					response.Data.InvitationSubData.push_back(invSubData);
				}
			}

			// Deserialize the "svr_data" part into SvrData object
			if (dataJson.contains("svr_data") && dataJson["svr_data"].is_object()) {
				nlohmann::json svr_dataJson = dataJson["svr_data"];
				response.Data.svr_data.fromJson(svr_dataJson);
			}

			// 从 JSON 数据中反序列化 OnlineClientData
			if (dataJson.contains("online_client") && dataJson["online_client"].is_object()) {
				nlohmann::json online_client_dataJson = dataJson["online_client"];
				response.Data.online_client.fromJson(online_client_dataJson);
			}
		}

		return true;
	}
	catch (const nlohmann::json::parse_error& e) {
		// Handle JSON parsing errors
		std::cerr << "JSON parse error: " << e.what() << std::endl;
		std::cerr << "Exception ID: " << e.id << std::endl;
		std::cerr << "Byte position of error: " << e.byte << std::endl;
		return false;
	}
	catch (const nlohmann::json::type_error& e) {
		// Handle type mismatch errors
		std::cerr << "JSON type error: " << e.what() << std::endl;
		return false;
	}
	catch (const std::exception& e) {
		// Catch any other unexpected errors
		std::cerr << "Unexpected error during JSON deserialization: " << e.what() << std::endl;
		return false;
	}
	catch (...) {
		// Catch all other exceptions
		std::cerr << "Unknown error occurred during JSON deserialization" << std::endl;
		return false;
	}
}

std::string ZoneHelperCore::GetLocalTimestamp() {

	return	std::to_string(GlobalClock::GetCurrentTimestamp());
}

//std::string ZoneHelperCore::GetLocalTimestamp() {
//
//	// Constructing it in place
//	wrap::Response r = wrap::HttpsRequest(wrap::Url{ "https://api.lzonel.com/" });
//	//std::cout << r.text << std::endl;
//
//	try {
//		auto j = nlohmann::json::parse(r.text);
//		if (j.contains("data") && j["data"].contains("l_cur_time")) {
//			//std::cout << j["data"]["l_cur_time"].get<std::string>();
//			return j["data"]["l_cur_time"].get<std::string>();
//		}
//	}
//	catch (const std::exception& e) {
//		std::cerr << "JSON parse error: " << e.what() << std::endl;
//	}
//	//获取失败
//	auto now = std::chrono::system_clock::now();
//	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
//	return std::to_string(ms);
//	//return "";
//}
/*
std::string ZoneHelperCore::GetLocalTimestamp() {


	//由于一些用户 本地时间与服务器时间不对应,所以这里采用获取网络时间
	auto now = std::chrono::system_clock::now();
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
	return std::to_string(ms);
}
*/

std::string ZoneHelperCore::ToPackPostData(const std::string& json_data) {
	std::string soft_encrypt_data = m_EncryptCore.ToEncrypt(json_data, EncryptKey, EncryptIv, EncryptMode);
	std::string time = GetLocalTimestamp();
	std::string c_data = SoftwareId + time + soft_encrypt_data + svr_EncryptSalt;
	std::string sign_md5 = m_EncryptCore.CalculateMD5Hash(c_data);
	std::string sign_crc8 = m_EncryptCore.CalculateCRC8(c_data);
	std::string sign_crc16 = m_EncryptCore.CalculateCRC16(c_data);
	std::string sign_crc32 = m_EncryptCore.CalculateCRC32(c_data);
	// 使用 std::transform 将 MD5 转为小写（避免 Windows tolower 宏与 lambda 冲突，使用函数指针形式）
	std::transform(sign_md5.begin(), sign_md5.end(), sign_md5.begin(),
		[](unsigned char c) { return static_cast<char>((std::tolower)(static_cast<unsigned char>(c))); });
	std::string data = R"(
        {
            "soft_id": ")" + SoftwareId + R"(",
            "soft_ver": ")" + soft_ver + R"(",
            "sdk_id": ")" + "2" + R"(",
            "sdk_ver": ")" + ZH_SDK_VER_STR + R"(",
            "time": ")" + time + R"(",
            "sign": ")" + sign_md5 + R"(",
            "s1": ")" + sign_crc8 + R"(",
            "s2": ")" + sign_crc16 + R"(",
            "s3": ")" + sign_crc32 + R"(",
            "soft_encrypt_data": ")" + m_EncryptCore.StringToHex(soft_encrypt_data) + R"("
        })";

	std::string enc_data = "";
	switch (EncryptMode)
	{
	case /*ns_ZoneHelper::*/eum_EncryptType::Plaintext:
	{
		enc_data = "[8]" + data;
		break;
	}
	case /*ns_ZoneHelper::*/eum_EncryptType::Base32:
	{
		enc_data = "[9]" + m_EncryptCore.ToEncrypt(data, svr_EncryptKey, svr_EncryptIv, eum_EncryptType::Base32);
		break;
	}
	case /*ns_ZoneHelper::*/eum_EncryptType::Base64:
	{
		enc_data = "[10]" + m_EncryptCore.ToEncrypt(data, svr_EncryptKey, svr_EncryptIv, eum_EncryptType::Base64);
		break;
	}
	case /*ns_ZoneHelper::*/eum_EncryptType::Hex:
	{
		enc_data = "[11]" + m_EncryptCore.ToEncrypt(data, svr_EncryptKey, svr_EncryptIv, eum_EncryptType::Hex);
		break;
	}
	default:
		enc_data = m_EncryptCore.ToEncrypt(data, svr_EncryptKey, svr_EncryptIv, eum_EncryptType::AES);
		break;
	}

	return enc_data;
}

std::string ZoneHelperCore::ToUnPackPostData(const std::string& json_data) {
	std::string res_data = "";
	std::string de_data = "";
	std::string usr_data = "";

	try {
		if (json_data.empty()) {
			return "";
		}

		switch (EncryptMode)
		{
		case /*ns_ZoneHelper::*/eum_EncryptType::Plaintext:
		{
			de_data = m_EncryptCore.ToDecrypt(json_data, svr_EncryptKey, svr_EncryptIv, eum_EncryptType::Plaintext);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::Base32:
		{
			de_data = m_EncryptCore.ToDecrypt(json_data, svr_EncryptKey, svr_EncryptIv, eum_EncryptType::Base32);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::Base64:
		{
			de_data = m_EncryptCore.ToDecrypt(json_data, svr_EncryptKey, svr_EncryptIv, eum_EncryptType::Base64);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::Hex:
		{
			de_data = m_EncryptCore.ToDecrypt(json_data, svr_EncryptKey, svr_EncryptIv, eum_EncryptType::Hex);
			break;
		}
		default:
			de_data = m_EncryptCore.ToDecrypt(json_data, svr_EncryptKey, svr_EncryptIv, eum_EncryptType::AES);
			break;
		}

        ApiResponse sys_response;
        if (!DeserializeJson(de_data, sys_response)) {
            std::cerr << "[Zone] outer response JSON parse failed, size="
                      << de_data.size() << '\n';
            return "";
        }

        std::string m_sign = m_EncryptCore.CalculateMD5Hash(this->SoftwareId + sys_response.Time + sys_response.Soft_encrypt_data + svr_EncryptSalt);//请求的签名,客户端可选签名校验
        if (sys_response.Sign != m_sign)
        {
            //响应签名有误!
            std::cerr << "[Zone] outer response signature mismatch\n";
            return "";
        }

        if (sys_response.Soft_encrypt_data.empty()) {
            std::cerr << "[Zone] outer response encrypted payload empty\n";
            return "";
        }

		usr_data = m_EncryptCore.HexToString(sys_response.Soft_encrypt_data);

        res_data = m_EncryptCore.ToDecrypt(usr_data, EncryptKey, EncryptIv, EncryptMode);
        if (res_data.empty()) {
            std::cerr << "[Zone] inner response decrypt failed\n";
            return "";
        }
	}
	catch (const std::exception& e) {
		(void)e;
	}

	return res_data;
}


std::string ZoneHelperCore::SendPostRequest(const std::string& apiUrl, const std::string& data) {
	//wrap::Response r = wrap::HttpsRequest(wrap::Url{ "https://api.lzonel.com/api/zone" },
	wrap::Response r = wrap::HttpsRequest(wrap::Url{ apiUrl },
		wrap::Body{ data },
		wrap::Header{ {"Content-Type", "application/json"} },
		wrap::Method{ "POST" });

	//std::cout << r.err << std::endl;

	return  r.text;
}
size_t ZoneHelperCore::WriteCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
	size_t totalSize = size * nmemb;
	response->append((char*)contents, totalSize);
	return totalSize;
}
std::string ZoneHelperCore::GetSocketMsg(const std::string& response_json) {
	std::string modified_response = response_json;
	while (modified_response == "1") {
		if (m_SocketReadMsgContainer.read_msg.size() > 0) {
			std::lock_guard<std::mutex> lock(m_SocketReadMsgContainer.lockObject);
			modified_response = m_SocketReadMsgContainer.read_msg[0];
			// 替换字符串中的 "zone"
			size_t pos = 0;
			while ((pos = modified_response.find("zone", pos)) != std::string::npos) {
				modified_response = modified_response.replace(pos, 4, "");
				pos += 1; // 将 pos 移动到下一个字符
			}
			m_SocketReadMsgContainer.read_msg.erase(m_SocketReadMsgContainer.read_msg.begin());
		}
		// 延时99毫秒
		std::this_thread::sleep_for(std::chrono::milliseconds(9));
		//std::cout << modified_response << std::endl;
		if (modified_response == "zone" || modified_response == "1" ||
			modified_response == "Message sent successfully" || modified_response == "sent successfully" ||
			modified_response.size() < 39) {
			modified_response = "1";
		}
		else {
			break;
		}
	}
	return modified_response;
}


std::string ZoneHelperCore::GetWebSocketMsg(const std::string& response_json) {
	// Early return if WebSocket is not connected
	if (!this->usr_webSocketClient->con_status) {
		return std::string(
			"{\"status\":\"200\",\"message\":\"Socket Invalid!\",\"code\":\"00001\","
			"\"data\":{\"run_status\":\"error\",\"Message\":\"WebSocket connection invalid\"}}");
	}

	std::string modified_response = response_json;
	const int MAX_ATTEMPTS = 100; // Prevent infinite loop
	int attempt = 0;

	while (attempt < MAX_ATTEMPTS) {
		// Check if there are messages in the container
		if (!this->usr_webSocketClient->msgContainer.read_msg.empty()) {
			// Thread-safe access to message container
			{
				std::lock_guard<std::mutex> lock(this->usr_webSocketClient->msgContainer.lockMutex);

				// Get the first message
				modified_response = *this->usr_webSocketClient->msgContainer.read_msg.begin();

				// Remove "zone" from the message
				size_t pos = 0;
				while ((pos = modified_response.find("zone", pos)) != std::string::npos) {
					modified_response.erase(pos, 4);
				}

				// Remove the processed message from the container
				this->usr_webSocketClient->msgContainer.read_msg.erase(
					this->usr_webSocketClient->msgContainer.read_msg.begin()
				);
			}

			// Filter out undesired messages
			const std::vector<std::string> INVALID_MESSAGES = {
				"zone", "1",
				"Message sent successfully",
				"sent successfully"
			};

			// Check if the message is valid
			bool is_invalid_message =
				modified_response.empty() ||
				modified_response.size() <= 39 ||
				std::any_of(INVALID_MESSAGES.begin(), INVALID_MESSAGES.end(),
					[&modified_response](const std::string& invalid_msg) {
						return modified_response == invalid_msg;
					}
			);

			if (!is_invalid_message) {
				return modified_response; // Valid message found
			}
		}

		// Small delay to prevent tight looping
		std::this_thread::sleep_for(std::chrono::milliseconds(9));

		attempt++;
	}

	// If no valid message found after max attempts
	return "1"; // Or handle this case as needed
}

std::string ZoneHelperCore::GetLocalMachineName() {
#if defined(_WIN32)
	char name[256] = {};
	DWORD size = sizeof(name);
	return GetComputerNameA(name, &size) ? std::string(name, size) : "";
#else
	char name[256] = {};
	return gethostname(name, sizeof(name)) == 0 ? std::string(name) : "";
#endif
}

std::string ZoneHelperCore::GetLocalIpAddress() {
#if defined(_WIN32)
	//std::string ipAddress;

	//return ipAddress;

	DWORD dwRetVal;
	IP_ADAPTER_INFO AdapterInfo[16];
	DWORD dwBufLen = sizeof(AdapterInfo);
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) != ERROR_SUCCESS)
		return "";

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
	while (pAdapterInfo) {
		if (pAdapterInfo->Type == MIB_IF_TYPE_ETHERNET && pAdapterInfo->IpAddressList.IpAddress.String[0] != '0') {
			return std::string(pAdapterInfo->IpAddressList.IpAddress.String);
		}
		pAdapterInfo = pAdapterInfo->Next;
	}

	return "";
#else
	return "";
#endif
}

std::string ZoneHelperCore::GetMacAddress() {
#if defined(_WIN32)
	//std::string macAddress;

	//return macAddress;

	IP_ADAPTER_INFO AdapterInfo[16];
	DWORD dwBufLen = sizeof(AdapterInfo);
	DWORD dwRetVal = 0;
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) != ERROR_SUCCESS)
		return "";

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
	while (pAdapterInfo) {
		if (pAdapterInfo->Type == MIB_IF_TYPE_ETHERNET)
			return std::string(pAdapterInfo->Address, pAdapterInfo->Address + pAdapterInfo->AddressLength);
		pAdapterInfo = pAdapterInfo->Next;
	}

	return "";
#else
	return "";
#endif
}

std::string ZoneHelperCore::GetSystemDiskSerialNumber() {
#if defined(_WIN32)
	//std::string serialNumber;

	//return serialNumber;
	DWORD serialNumber;
	if (GetVolumeInformationA("C:\\", nullptr, 0, &serialNumber, nullptr, nullptr, nullptr, 0))
		return std::to_string(serialNumber);

	return "";
#else
	return "";
#endif
}

void ZoneHelperCore::zoneInit() {
	// 获取机器名
	this->MachineName = GetLocalMachineName();

	// 获取本地IP地址
	this->IP = GetLocalIpAddress();

	std::string machine_guid;
	std::string bios_serial;
	std::string disk_serial;
	std::string temp_MacCode;
	std::string cpu_id;
	std::string board_serial;
	get_machine_guid(machine_guid);
	get_bios_serial(bios_serial);
	get_os_disk_serial(disk_serial);
	get_cpu_id(cpu_id);
	get_board_serial_number(board_serial);
	get_mac_address(temp_MacCode);

	// Android 优先使用 vbmeta/序列号等稳定标识，避免 boot_id、网卡等可变字段导致设备码漂移。
	std::string all_s = machine_guid;
	if (all_s.empty()) {
		all_s = hw_normalize_token(bios_serial) + "|" + hw_normalize_token(disk_serial) +
			"|" + temp_MacCode + "|" + hw_normalize_token(cpu_id) + "|" +
			hw_normalize_token(board_serial);
	}
	this->MacCode = m_EncryptCore.CalculateMD5Hash(all_s);
	// Console.WriteLine(this.MacCode);    

	//获取服务器时间
	long long svr_time_ms = 0;
	ApiResponse tmp_ApiResponse;

	// 先调用获取服务器时间的接口
	bool getTimeSuccess = this->GetTimeStamp(tmp_ApiResponse);

	// 核心判断：如果时间戳为空，直接用本地时间
	if (tmp_ApiResponse.Data.Timestamp_ms.empty())
	{
		// 服务器时间为空，使用本地时间
		auto now = std::chrono::system_clock::now();
		svr_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
	}
	else
	{
		// 时间戳非空，尝试转换
		try {
			svr_time_ms = std::stoll(tmp_ApiResponse.Data.Timestamp_ms);
		}
		catch (...) {
			// 转换失败时，降级使用本地时间
			auto now = std::chrono::system_clock::now();
			svr_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
		}
	}

	GlobalClock::Start(svr_time_ms);
}

std::string ZoneHelperCore::string_To_UTF8(const std::wstring& wstr)
{
	std::string ret;
	try {
		std::wstring_convert< std::codecvt_utf8<wchar_t> > wcv;
		ret = wcv.to_bytes(wstr);
	}
	catch (const std::exception& e) {
		std::cerr << e.what() << std::endl;
	}
	return ret;
}

std::string ZoneHelperCore::UnicodeToUTF8(const std::wstring& wstr)
{
	std::string ret;
	try {
		std::wstring_convert< std::codecvt_utf8<wchar_t> > wcv;
		ret = wcv.to_bytes(wstr);
	}
	catch (const std::exception& e) {
		std::cerr << e.what() << std::endl;
	}
	return ret;
}

std::wstring ZoneHelperCore::UTF8ToUnicode(const std::string& str)
{
	std::wstring ret;
	try {
		std::wstring_convert< std::codecvt_utf8<wchar_t> > wcv;
		ret = wcv.from_bytes(str);
	}
	catch (const std::exception& e) {
		std::cerr << e.what() << std::endl;
	}
	return ret;
}

std::string ZoneHelperCore::UnicodeToANSI(const std::wstring& wstr)
{
	std::string ret;
	std::mbstate_t state = {};
	const wchar_t* src = wstr.data();
	size_t len = std::wcsrtombs(nullptr, &src, 0, &state);
	if (static_cast<size_t>(-1) != len) {
		std::unique_ptr< char[] > buff(new char[len + 1]);
		len = std::wcsrtombs(buff.get(), &src, len, &state);
		if (static_cast<size_t>(-1) != len) {
			ret.assign(buff.get(), len);
		}
	}
	return ret;
}

std::wstring ZoneHelperCore::ANSIToUnicode(const std::string& str)
{
	std::wstring ret;
	std::mbstate_t state = {};
	const char* src = str.data();
	size_t len = std::mbsrtowcs(nullptr, &src, 0, &state);
	if (static_cast<size_t>(-1) != len) {
		std::unique_ptr< wchar_t[] > buff(new wchar_t[len + 1]);
		len = std::mbsrtowcs(buff.get(), &src, len, &state);
		if (static_cast<size_t>(-1) != len) {
			ret.assign(buff.get(), len);
		}
	}
	return ret;
}

std::string ZoneHelperCore::UTF8ToANSI(const std::string& str)
{
	return UnicodeToANSI(UTF8ToUnicode(str));
}

std::string ZoneHelperCore::ANSIToUTF8(const std::string& str)
{
	return UnicodeToUTF8(ANSIToUnicode(str));
}

std::string ZoneHelperCore::escapeJSONSpecialChars(const std::string& str) {
	std::string escapedStr;
	for (char ch : str) {
		switch (ch) {
		case '"':
			escapedStr += "\\\"";
			break;
		case '\\':
			escapedStr += "\\\\";
			break;
		case '\n':
			escapedStr += "\\n";
			break;
		case '\t':
			escapedStr += "\\t";
			break;
		case '\r':
			escapedStr += "\\r";
			break;
		case '\b':
			escapedStr += "\\b";
			break;
		case '\f':
			escapedStr += "\\f";
			break;
		default:
			escapedStr += ch;
			break;
		}
	}
	return escapedStr;
}
std::string ZoneHelperCore::escapeJson(const std::string& input) {
	std::string output;
	output.reserve(input.length() * 2); // 预留足够的空间以避免不必要的内存分配

	for (char ch : input) {
		switch (ch) {
		case '"':
			output += "\\\"";
			break;
		case '\\':
			output += "\\\\";
			break;
		case '\b':
			output += "\\b";
			break;
		case '\f':
			output += "\\f";
			break;
		case '\n':
			output += "\\n";
			break;
		case '\r':
			output += "\\r";
			break;
		case '\t':
			output += "\\t";
			break;
			// 其他不需要转义的字符直接添加到输出字符串中
		default:
			output += ch;
			break;
		}
	}

	return output;
}




int ZoneHelperCore::findPostMethod(int post_method, const std::string& c_em_list)
{
	// 将字符串转换为ASCII编码的字节数组
	std::vector<unsigned char> asciiBytes(c_em_list.begin(), c_em_list.end());

	// 打印ASCII编码的字节数组
	// std::cout << "ASCII 编码的字节数组:" << std::endl;
	int i = 0;
	for (unsigned char b : asciiBytes)
	{
		// std::cout << static_cast<int>(b) << " ";
		if (i == post_method)
		{
			return b;
		}
		i++;
	}

	return 15;
}

int ZoneHelperCore::CalcPostMethod(long long postTimes, int postMethod) {
	// Convert milliseconds to seconds
	long long seconds = postTimes / 1000;

	// Convert seconds to tm structure
	time_t rawtime = seconds;
	struct tm* timeinfo = localtime(&rawtime);

	// Get the minutes from the time structure
	int minutes = timeinfo->tm_min;

	switch (minutes) {
	case 0: return findPostMethod(postMethod, c_em_list_0);
	case 1: return findPostMethod(postMethod, c_em_list_1);
	case 2: return findPostMethod(postMethod, c_em_list_2);
	case 3: return findPostMethod(postMethod, c_em_list_3);
	case 4: return findPostMethod(postMethod, c_em_list_4);
	case 5: return findPostMethod(postMethod, c_em_list_5);
	case 6: return findPostMethod(postMethod, c_em_list_6);
	case 7: return findPostMethod(postMethod, c_em_list_7);
	case 8: return findPostMethod(postMethod, c_em_list_8);
	case 9: return findPostMethod(postMethod, c_em_list_9);
	case 10: return findPostMethod(postMethod, c_em_list_10);
	case 11: return findPostMethod(postMethod, c_em_list_11);
	case 12: return findPostMethod(postMethod, c_em_list_12);
	case 13: return findPostMethod(postMethod, c_em_list_13);
	case 14: return findPostMethod(postMethod, c_em_list_14);
	case 15: return findPostMethod(postMethod, c_em_list_15);
	case 16: return findPostMethod(postMethod, c_em_list_16);
	case 17: return findPostMethod(postMethod, c_em_list_17);
	case 18: return findPostMethod(postMethod, c_em_list_18);
	case 19: return findPostMethod(postMethod, c_em_list_19);
	case 20: return findPostMethod(postMethod, c_em_list_20);
	case 21: return findPostMethod(postMethod, c_em_list_21);
	case 22: return findPostMethod(postMethod, c_em_list_22);
	case 23: return findPostMethod(postMethod, c_em_list_23);
	case 24: return findPostMethod(postMethod, c_em_list_24);
	case 25: return findPostMethod(postMethod, c_em_list_25);
	case 26: return findPostMethod(postMethod, c_em_list_26);
	case 27: return findPostMethod(postMethod, c_em_list_27);
	case 28: return findPostMethod(postMethod, c_em_list_28);
	case 29: return findPostMethod(postMethod, c_em_list_29);
	case 30: return findPostMethod(postMethod, c_em_list_30);
	case 31: return findPostMethod(postMethod, c_em_list_31);
	case 32: return findPostMethod(postMethod, c_em_list_32);
	case 33: return findPostMethod(postMethod, c_em_list_33);
	case 34: return findPostMethod(postMethod, c_em_list_34);
	case 35: return findPostMethod(postMethod, c_em_list_35);
	case 36: return findPostMethod(postMethod, c_em_list_36);
	case 37: return findPostMethod(postMethod, c_em_list_37);
	case 38: return findPostMethod(postMethod, c_em_list_38);
	case 39: return findPostMethod(postMethod, c_em_list_39);
	case 40: return findPostMethod(postMethod, c_em_list_40);
	case 41: return findPostMethod(postMethod, c_em_list_41);
	case 42: return findPostMethod(postMethod, c_em_list_42);
	case 43: return findPostMethod(postMethod, c_em_list_43);
	case 44: return findPostMethod(postMethod, c_em_list_44);
	case 45: return findPostMethod(postMethod, c_em_list_45);
	case 46: return findPostMethod(postMethod, c_em_list_46);
	case 47: return findPostMethod(postMethod, c_em_list_47);
	case 48: return findPostMethod(postMethod, c_em_list_48);
	case 49: return findPostMethod(postMethod, c_em_list_49);
	case 50: return findPostMethod(postMethod, c_em_list_50);
	case 51: return findPostMethod(postMethod, c_em_list_51);
	case 52: return findPostMethod(postMethod, c_em_list_52);
	case 53: return findPostMethod(postMethod, c_em_list_53);
	case 54: return findPostMethod(postMethod, c_em_list_54);
	case 55: return findPostMethod(postMethod, c_em_list_55);
	case 56: return findPostMethod(postMethod, c_em_list_56);
	case 57: return findPostMethod(postMethod, c_em_list_57);
	case 58: return findPostMethod(postMethod, c_em_list_58);
	case 59: return findPostMethod(postMethod, c_em_list_59);
	default: return 15;
	}
}



bool ZoneHelperCore::ToWrite(std::string requestData, std::string time, ApiResponse& response)
{
	std::string apiUrl = svr_Host + svr_zone_path;
	try
	{
		EncodeMachineNamesForWire(requestData);
		std::string packed_data = ToPackPostData(requestData);
		std::string response_json = "";
#ifdef XOLLVM_ZONE_DEBUG_PKT
		std::cerr << "[Zone][pkt] >>> POST " << apiUrl << "\n"
			<< "[Zone][pkt] >>> plain request:\n" << requestData << "\n"
			<< "[Zone][pkt] >>> packed request(size=" << packed_data.size() << "):\n"
			<< packed_data << "\n";
#endif
		if (Z_AgreementType == eum_AgreementType::SOCKET)
		{
			// response_json = SendPostRequest(apiUrl, packed_data);
			response_json = usr_SocketClientCore->SendMessageS(packed_data);//2024-04-09, 07:47:12.729588 [info] - 0       1==发送消息成功
			response_json = GetSocketMsg(response_json);//获取Socket返回消息,
			//std::cout << response_json;
		}
		else if (Z_AgreementType == eum_AgreementType::WebSocket || Z_AgreementType == eum_AgreementType::WebSockets)
		{
			this->usr_webSocketClient->SendMessageWs(packed_data);

			response_json = GetWebSocketMsg(response_json);//获取WebSocket返回消息,
		}
		else if (Z_AgreementType == eum_AgreementType::HTTP || Z_AgreementType == eum_AgreementType::HTTPS)
		{
			response_json = SendPostRequest(apiUrl, packed_data);
		}

#ifdef XOLLVM_ZONE_DEBUG_PKT
		std::cerr << "[Zone][pkt] <<< raw response(size=" << response_json.size() << "):\n"
			<< response_json << "\n";
#endif

		const std::string unpacked = ToUnPackPostData(response_json);
		if (unpacked.empty()) {
#ifdef XOLLVM_ZONE_DEBUG_PKT
			std::cerr << "[Zone][pkt] !! unpack failed (empty) -- see [Zone] lines above for the exact stage\n";
#endif
			return false;
		}
#ifdef XOLLVM_ZONE_DEBUG_PKT
		std::cerr << "[Zone][pkt] <<< unpacked(size=" << unpacked.size() << "):\n"
			<< unpacked << "\n";
#endif
		if (!DeserializeJson(unpacked, response)) {
#ifdef XOLLVM_ZONE_DEBUG_PKT
			std::cerr << "[Zone][pkt] !! DeserializeJson failed on unpacked payload\n";
#endif
			return false;
		}

		if ("success" == response.Data.Run_status && "" != response.Data.Token)
		{
			usr_token = response.Data.Token;
		}

		return true;
	}
	catch (const std::exception& e)
	{
		std::cerr << "HTTP POST Error :" << e.what() << std::endl;
	}

	return false;
}


std::string ZoneHelperCore::ReplaceMethodValue(const std::string& jsonData, const std::string& newMethod) {
	// Regular expression pattern to match the "method" field
	std::string pattern = R"("method"\s*:\s*"[^"]*")";
	// Replacement string with the new method
	std::string replacement = "\"method\": \"" + newMethod + "\"";

	// Use std::regex_replace to replace the matched pattern with the replacement string
	std::regex re(pattern);
	return std::regex_replace(jsonData, re, replacement);
}


//bool ZoneHelperCore::ToMoreWrite(const std::string& requestData, const std::string& time, ApiResponse& response)
//{
//	std::random_device rd;
//	std::mt19937 gen(rd());
//	std::uniform_int_distribution<> dist1(1, 2);//[2,3]
//	int randomNumber = dist1(gen);
//	std::uniform_int_distribution<> dist2(0, randomNumber - 1);//[0,1]|[0,2]
//	std::uniform_int_distribution<> dist3(257, 369);
//	int randomNumber2 = dist2(gen);
//	try {
//
//		for (int i = 0; i < randomNumber; ++i) {
//			int randomNumber3 = dist3(gen);
//			std::string requestData_temp = ReplaceMethodValue(requestData, std::to_string(randomNumber3));
//
//			ApiResponse _response;
//			ToWrite(requestData_temp, time, _response);
//
//			std::this_thread::sleep_for(std::chrono::milliseconds(1)); // Delay 1ms to prevent duplicate requests
//
//			if (i == randomNumber2) {
//				return ToWrite(requestData, time, response);
//			}
//		}
//	}
//	catch (const std::exception&) {
//		// Handle the exception
//	}
//
//	return false;
//}

bool ZoneHelperCore::ToMoreWrite(const std::string& requestData, const std::string& time, ApiResponse& response)
{
	try {
		std::this_thread::sleep_for(std::chrono::milliseconds(1)); // Delay 1ms to prevent duplicate requests
		return ToWrite(requestData, time, response);
	}
	catch (const std::exception&) {
	}
	return false;
}
