#include "ZoneLib.h"
#include "../ZoneHelper.h"
#include "ZoneHelperCore.h"

using namespace std;

ZoneHelperCore* zoneHelper = nullptr;


/// <summary>
/// ZoneHelper初始化参数,必须首先调用初始化
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_SoftwareId">客户端ID</param>
/// <param name="arg_soft_ver">软件版本号</param>
/// <param name="arg_EncryptKey">加密key</param>
/// <param name="arg_EncryptIv">加密iv</param>
/// <param name="arg_encryptType">加密类型:0=AES,1=RC4,2=DES3,3=ChaCha20,4=RSA,5=NTRU,6=ECC</param>
/// <param name="arg_LoginType">登录方式:0=Card,1=Account</param>
/// <param name="arg_AgreementType">通讯协议:0=HTTP,1=HTTPS,2=SOCKET,3=WebSocket,4=WebSockets</param>
/// <param name="arg_NetworkRegion">网络分区:1=中国境内,2=中国境外,3=全球（默认3）；决定从集群列表中筛选的线路，并在同类节点中随机选取</param>
/// <returns>0=请求失败,1=请求成功</returns>

ZoneHelper::ZoneHelper(const  std::string& arg_SoftwareId, const  std::string& arg_soft_ver, const  std::string& arg_EncryptKey, const  std::string& arg_EncryptIv, const eum_EncryptType& arg_encryptType, const eum_LoginType& arg_LoginType, const eum_AgreementType& arg_AgreementType, eum_NetworkRegion arg_NetworkRegion)
{
	zoneHelper = new ZoneHelperCore(arg_SoftwareId, arg_soft_ver, arg_EncryptKey, arg_EncryptIv, arg_encryptType, arg_LoginType, arg_AgreementType, arg_NetworkRegion);
	if (nullptr == zoneHelper)
	{
		throw std::runtime_error("ZoneHelperCore allocation failed");
		//return 0;
	}
	//return 1;
}
ZoneHelper::~ZoneHelper()
{
	delete zoneHelper;
	zoneHelper = nullptr;
}

std::string ZoneHelper::get_sdk_ver()
{
	return ZH_SDK_VER_STR;
}

/// <summary>
/// 查询卡密的状态
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_card"></param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::QueryCard(ApiResponse& out_ApiResponse, const  std::string& arg_card)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}

	if (!zoneHelper->QueryCard(arg_card, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}

	return 1;
}

/// <summary>
/// 解绑卡密
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_card"></param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::UnbindCard(ApiResponse& out_ApiResponse, const  std::string& arg_card)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}

	if (!zoneHelper->UnbindCard(arg_card, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

/// <summary>
/// 卡密登录返回心跳所用的Token
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_card">完整卡密</param>
/// <param name="arg_InvitationCode">邀请码(选填,首次登录的卡密激活)</param>
/// <param name="arg_VerifyCode">验证码(选填)</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::LoginC(ApiResponse& out_ApiResponse, const std::string& arg_card, std::string arg_InvitationCode, std::string arg_VerifyCode)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->LoginC(arg_card, arg_InvitationCode, arg_VerifyCode, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}


/// <summary>
/// 使用卡密给卡密充值
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_card">卡密</param>
/// <param name="arg_RechargeCard">充值卡</param>
/// <param name="arg_VerifyCode">验证码(选填)</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::RechargeC(ApiResponse& out_ApiResponse, const std::string& arg_card, const std::string& arg_RechargeCard, std::string arg_VerifyCode)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}

	if (!zoneHelper->RechargeC(arg_card, arg_RechargeCard, arg_VerifyCode, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}


/// <summary>
/// 账号查询返回这个账号的信息
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_Account"></param>
/// <param name="arg_Password"></param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::QueryAccount(ApiResponse& out_ApiResponse, const  std::string& arg_Account, const  std::string& arg_Password)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}

	if (!zoneHelper->QueryAccount(arg_Account, arg_Password, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

/// <summary>
/// 解绑账号,返回剩余解绑次数以及时间和点数
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_Account"></param>
/// <param name="arg_Password"></param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::UnbindAccount(ApiResponse& out_ApiResponse, const  std::string& arg_Account, const  std::string& arg_Password)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}

	if (!zoneHelper->UnbindAccount(arg_Account, arg_Password, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}


/// <summary>
/// 账号登录返回心跳所用的Token
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_Account">账号</param>
/// <param name="arg_Password">密码</param>
/// <param name="arg_VerifyCode">验证码(选填)</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::LoginA(ApiResponse& out_ApiResponse, const std::string& arg_Account, const std::string& arg_Password, std::string arg_VerifyCode)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}

	if (!zoneHelper->LoginA(arg_Account, arg_Password, arg_VerifyCode, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

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
int ZoneHelper::Register(ApiResponse& out_ApiResponse, const std::string& arg_Account, const std::string& arg_Password, const std::string& arg_card, std::string arg_ContactInfo, eum_ContactType arg_ContactType, std::string arg_InvitationCode, std::string arg_VerifyCode)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->Register(arg_Account, arg_Password, arg_card, arg_ContactInfo, arg_ContactType, arg_InvitationCode, arg_VerifyCode, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

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
int ZoneHelper::ChangePasswordA(ApiResponse& out_ApiResponse, const std::string& arg_Account, const std::string& arg_NewPassword, std::string arg_ContactInfo, eum_ContactType arg_ContactType, std::string arg_VerifyCode)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}

	if (!zoneHelper->ChangePasswordA(arg_Account, arg_NewPassword, arg_ContactInfo, arg_ContactType, arg_VerifyCode, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}


/// <summary>
/// 使用卡密给账号充值
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_Account">账号</param>
/// <param name="arg_Password">密码</param>
/// <param name="arg_RechargeCard">充值卡</param>
/// <param name="arg_VerifyCode">验证码(选填)</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::RechargeA(ApiResponse& out_ApiResponse, const std::string& arg_Account, const std::string& arg_Password, const std::string& arg_RechargeCard, std::string arg_VerifyCode)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->RechargeA(arg_Account, arg_Password, arg_RechargeCard, arg_VerifyCode, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}


/// <summary>
/// 账号/卡密 的心跳
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::HeartBeat(ApiResponse& out_ApiResponse)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}

	if (!zoneHelper->HeartBeat(out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

/// <summary>
/// 账号/卡密 扣点数
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_score">0=扣点1,整数型,如果是乱七八糟的字符或者<0的 均按照1处理</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::SubScore(ApiResponse& out_ApiResponse, int arg_score)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->SubScore(arg_score, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

/// <summary>
 /// 获取云变量
 /// </summary>
 /// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
 /// <param name="arg_VariableName">云变量Name</param>
 /// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::GetAntiVariableValue(ApiResponse& out_ApiResponse, const  std::string& arg_VariableName)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->GetAntiVariableValue(arg_VariableName, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

/// <summary>
/// 获取云算法
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_AlgorithmName">云算法Name</param>
/// <param name="arg_ReqArguments">[选填]云算法参数,若为空则自动使用后台设置的参数</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::GetAntiAlgorithmValue(ApiResponse& out_ApiResponse, const  std::string& arg_AlgorithmName, std::string arg_ReqArguments)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->GetAntiAlgorithmValue(arg_AlgorithmName, arg_ReqArguments, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

/// <summary>
/// 获取软件信息,用于更新操作,以及获取软件的公告信息
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::GetSoftInfo(ApiResponse& out_ApiResponse)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}

	if (!zoneHelper->GetSoftInfo(out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

/// <summary>
/// 反馈消息
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_Msg_body"></param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::FeedBack(ApiResponse& out_ApiResponse, const  std::string& arg_Msg_body)
{
	return FeedBackWithVerifyCode(out_ApiResponse, arg_Msg_body, "");
}

int ZoneHelper::FeedBackWithVerifyCode(ApiResponse& out_ApiResponse, const std::string& arg_Msg_body,
	const std::string& arg_VerifyCode)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->FeedBackWithVerifyCode(arg_Msg_body, arg_VerifyCode, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

/// <summary>
/// 日志消息
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_Msg_body"></param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::Log(ApiResponse& out_ApiResponse, const  std::string& arg_Msg_body)
{
	return Log(out_ApiResponse, arg_Msg_body, "none", "");
}

int ZoneHelper::Log(ApiResponse& out_ApiResponse, const std::string& arg_Msg_body,
	const std::string& arg_LogLevel, const std::string& arg_CustomType)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->Log(arg_Msg_body, arg_LogLevel, arg_CustomType, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}


/// <summary>
/// 游客(试用)登录返回心跳所用的Token
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_VerifyCode">验证码(选填)</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::LoginT(ApiResponse& out_ApiResponse, std::string arg_VerifyCode)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->TryIt(arg_VerifyCode, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

/// <summary>
/// 获取客户端配置信息
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::GetClientConfig(ApiResponse& out_ApiResponse)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->GetConfig(out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

int ZoneHelper::DownloadCloudFile(ApiResponse& out_ApiResponse,
	const std::string& fileIdentifier, const std::string& version, const std::string& requestId)
{
	if (nullptr == zoneHelper)
		return 0;
	return zoneHelper->DownloadCloudFile(fileIdentifier, version, requestId, out_ApiResponse) ? 1 : 0;
}

int ZoneHelper::ListVersions(ApiResponse& out_ApiResponse, int page, int pageSize)
{
	if (nullptr == zoneHelper)
		return 0;
	return zoneHelper->ListVersions(page, pageSize, out_ApiResponse) ? 1 : 0;
}

int ZoneHelper::FeedbackList(ApiResponse& out_ApiResponse, int page, int pageSize)
{
	if (nullptr == zoneHelper)
		return 0;
	return zoneHelper->FeedbackList(page, pageSize, out_ApiResponse) ? 1 : 0;
}


/// <summary>
/// 编辑客户端配置信息
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_Config"></param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::EditClientConfig(ApiResponse& out_ApiResponse, const std::string& arg_Config)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->EditConfig(arg_Config, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}


/// <summary>
/// 清空客户端配置信息
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::ClearClientConfig(ApiResponse& out_ApiResponse)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->ClearConfig(out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}


/// <summary>
/// 获取验证码
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::GetCaptcha(ApiResponse& out_ApiResponse)
{
	return GetCaptchaWithScene(out_ApiResponse, "");
}

int ZoneHelper::GetCaptchaWithScene(ApiResponse& out_ApiResponse, const std::string& arg_CaptchaScene)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->GetVerifyCodeWithScene(arg_CaptchaScene, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}


/// <summary>
/// 获取邀请成果
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::GetInviteHarvest(ApiResponse& out_ApiResponse)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->GetInviteHarvest(out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}


/// <summary>
/// 获取邀请记录列表
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::GetInviteRecord(ApiResponse& out_ApiResponse)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->GetInviteRecord(out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

/// <summary>
/// 获取服务器时间
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::GetTimeStamp(ApiResponse& out_ApiResponse)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->GetTimeStamp(out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

/// <summary>
/// 登出
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::Logout(ApiResponse& out_ApiResponse)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->Logout(out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 查询在线设备(卡密)
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_card">完整卡密</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::QueryOnlineDeviceC(ApiResponse& out_ApiResponse, const std::string& arg_card)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->QueryOnlineDeviceC(arg_card, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 踢掉在线设备(卡密)
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_card">完整卡密</param>
/// <param name="arg_index">踢掉索引号,-1代表全踢</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::KickOnlineDeviceC(ApiResponse& out_ApiResponse, const std::string& arg_card, int arg_index)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->KickOnlineDeviceC(arg_card, arg_index, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 查询在线设备(账号)
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_Account">账号</param>
/// <param name="arg_Password">密码</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::QueryOnlineDeviceA(ApiResponse& out_ApiResponse, const std::string& arg_Account, const std::string& arg_Password)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->QueryOnlineDeviceA(arg_Account, arg_Password, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 踢掉在线设备(账号)
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <param name="arg_Account">账号</param>
/// <param name="arg_Password">密码</param>
/// <param name="arg_index">踢掉索引号,-1代表全踢</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::KickOnlineDeviceA(ApiResponse& out_ApiResponse, const std::string& arg_Account, const std::string& arg_Password, int arg_index)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->KickOnlineDeviceA(arg_Account, arg_Password, arg_index, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 获取服务器线路
/// </summary>
/// <param name="out_ApiResponse">响应数据:由服务器反馈响应数据,具体请参考[开发手册]</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::GetSvrNodes(ApiResponse& out_ApiResponse)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->GetSvrNodes(out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
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
int ZoneHelper::ChangeSvrNode(ApiResponse& out_ApiResponse, const std::string& arg_http_address, const std::string& arg_https_address, const std::string& arg_socket_address, const std::string& arg_ws_address, const std::string& arg_wss_address)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->ChangeSvrNode(arg_http_address, arg_https_address, arg_socket_address, arg_ws_address, arg_wss_address, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}

/// <summary>
	/// 发起签到
	/// </summary>
	/// <param name="response"></param>
	/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::SignIn(ApiResponse& out_ApiResponse)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->SignIn(out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 发起补签
/// </summary>
/// <param name="response"></param>
/// <param name="arg_TimeStamp_s">补签的时间戳,单位:秒(s)</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::SignInFix(ApiResponse& out_ApiResponse, const std::string& arg_TimeStamp_s)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->SignInFix(arg_TimeStamp_s, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 查询签到历史
/// </summary>
/// <param name="response"></param>
/// <param name="arg_Page">页面,默认:1</param>
/// <param name="arg_PageSize">页面大小,默认:20</param>
/// <param name="arg_TimeOrder">顺序,0=最新数据->旧数据,1=旧数据->新数据</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::SignInQueryHistory(ApiResponse& out_ApiResponse, std::string arg_Page, std::string arg_PageSize, std::string arg_TimeOrder)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->SignInQueryHistory(arg_Page, arg_PageSize, arg_TimeOrder, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 查询等级列表
/// </summary>
/// <param name="response"></param>
/// <param name="arg_Page">页面,默认:1</param>
/// <param name="arg_PageSize">页面大小,默认:20</param>
/// <param name="arg_TimeOrder">顺序,0=最新数据->旧数据,1=旧数据->新数据</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::GradeQueryList(ApiResponse& out_ApiResponse, std::string arg_Page, std::string arg_PageSize, std::string arg_TimeOrder)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->GradeQueryList(arg_Page, arg_PageSize, arg_TimeOrder, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 查询抽奖列表
/// </summary>
/// <param name="response"></param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::LotteryQueryList(ApiResponse& out_ApiResponse)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->LotteryQueryList(out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 发起抽奖(包含连抽)
/// </summary>
/// <param name="response"></param>
/// <param name="arg_Num">连抽数量,默认:1</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::LotteryStart(ApiResponse& out_ApiResponse, std::string arg_Num)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->LotteryStart(arg_Num, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 查询抽奖历史
/// </summary>
/// <param name="response"></param>
/// <param name="arg_Page">页面,默认:1</param>
/// <param name="arg_PageSize">页面大小,默认:20</param>
/// <param name="arg_TimeOrder">顺序,0=最新数据->旧数据,1=旧数据->新数据</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::LotteryQueryHistory(ApiResponse& out_ApiResponse, std::string arg_Page, std::string arg_PageSize, std::string arg_TimeOrder)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->LotteryQueryHistory(arg_Page, arg_PageSize, arg_TimeOrder, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 查询商城物品列表
/// </summary>
/// <param name="response"></param>
/// <param name="arg_Page">页面,默认:1</param>
/// <param name="arg_PageSize">页面大小,默认:20</param>
/// <param name="arg_TimeOrder">顺序,0=最新数据->旧数据,1=旧数据->新数据</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::ShopQueryList(ApiResponse& out_ApiResponse, std::string arg_Page, std::string arg_PageSize, std::string arg_TimeOrder)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->ShopQueryList(arg_Page, arg_PageSize, arg_TimeOrder, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 购买/兑换物品
/// </summary>
/// <param name="response"></param>
/// <param name="arg_Id"></param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::ShopBuy(ApiResponse& out_ApiResponse, const std::string& arg_Id)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->ShopBuy(arg_Id, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}
/// <summary>
/// 查询购买过的物品记录列表
/// </summary>
/// <param name="response"></param>
/// <param name="arg_Page">页面,默认:1</param>
/// <param name="arg_PageSize">页面大小,默认:20</param>
/// <param name="arg_TimeOrder">顺序,0=最新数据->旧数据,1=旧数据->新数据</param>
/// <returns>0=请求失败,1=请求成功</returns>
int ZoneHelper::ShopQueryHistory(ApiResponse& out_ApiResponse, std::string arg_Page, std::string arg_PageSize, std::string arg_TimeOrder)
{
	if (nullptr == zoneHelper)
	{
		std::cerr << "new faile zoneHelper" << std::endl;
		return 0;
	}
	if (!zoneHelper->ShopQueryHistory(arg_Page, arg_PageSize, arg_TimeOrder, out_ApiResponse))
	{
		std::cerr << "Post Error!" << std::endl;
		return 0;
	}
	return 1;
}



