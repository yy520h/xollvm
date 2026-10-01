#pragma once
#include "ZoneLib.h"
#include "EncryptCore.h"
#include "SocketClientCore.h"
//#include "cpprest/http_client.h"
//#include "cpprest/details/basic_types.h"
#include "nlohmann/json.hpp"
#include <locale>
#include <codecvt>
//#include <curl/curl.h>

#if defined(_WIN32)
#include <iphlpapi.h>
#include <lmcons.h>
#include <Windows.h>
#endif
#include <regex>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <random>
#include <chrono>
#include "WebSocketClient.hpp"
#include "WNetWrap/wnetwrap.h"
#include "hw_info.h"
#include "GlobalClock.h"

#if defined(_WIN32)
#pragma comment(lib, "iphlpapi.lib")
#endif

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable: 4996)

#ifndef ZH_SDK_VER_STR
#define ZH_SDK_VER_STR "1001"
#endif

class ZoneHelperCore {
private:
	std::string SoftwareId;
	std::string soft_ver;
	std::string EncryptKey;
	std::string EncryptIv;
	eum_EncryptType EncryptMode;
	eum_LoginType Z_LoginType;
	eum_AgreementType Z_AgreementType;
	std::string svr_EncryptKey = "e4b190bd550c9cef";
	std::string svr_EncryptIv = "402a388747e7bd8f";
	std::string svr_EncryptSalt = "lzonel";

	std::string svr_Host = "api.lzonel.com";
	std::string svr_address = "211.154.22.112";
	int svr_port = 30001;
	std::string svr_wss_Host = "api.lzonel.com";
	eum_NetworkRegion Z_NetworkRegion = eum_NetworkRegion::Global;
	/// <summary>业务 API 路径，与 svr_Host 拼接为完整 URL（来自集群列表的 path，默认 /api/zone）</summary>
	std::string svr_zone_path = "/api/zone";
	std::string svr_ws_full_url;
	std::string svr_wss_full_url;
	std::string cluster_http_origin;
	std::string cluster_https_origin;

	//std::string svr_Host = "192.168.5.69:8001";//Debug  wnetwrap_handleURI尚未实现 ip端口形式解析[2025年8月15日10:13:39]
	//std::string svr_address = "192.168.5.69";//Debug
	//int svr_port = 8003;//Debug
	//std::string svr_wss_Host = "192.168.5.69:8004";//WebSocket 地址 Debug

	//std::string svr_address = "121.43.118.53";
	//int svr_port = 30001;

	SocketClientCore* usr_SocketClientCore = nullptr;
	bool socket_con_status = false;
	SocketReadMsgContainer m_SocketReadMsgContainer;
	ZoneWebSocketClient* usr_webSocketClient = nullptr;//ws/wss
	std::string IP;
	std::string MachineName;
	std::string MacCode;
	std::string usr_token;
	EncryptCore m_EncryptCore;

	std::string card_head, card;
	std::string account, password;

	std::string verifyID;
	std::string fingerprint;

	int on_TryMode = 0;//0=不处于试用,1=处于试用状态

private:
	std::string GetLocalMachineName();
	std::string GetLocalIpAddress();
	std::string GetMacAddress();
	std::string GetSystemDiskSerialNumber();
	void zoneInit();
	wrap::Response SendGetRequestRaw(const std::string& url);
	bool tryApplyClusterEndpoints();
	void applyLegacyDefaultEndpoints();

public:
	ZoneHelperCore();
	ZoneHelperCore(const std::string& arg_SoftwareId, const std::string& arg_soft_ver, const std::string& arg_EncryptKey, const std::string& arg_EncryptIv, eum_EncryptType arg_encryptType, eum_LoginType arg_LoginType, eum_AgreementType arg_AgreementType, eum_NetworkRegion arg_NetworkRegion);
	~ZoneHelperCore();

	bool QueryCard(const std::string& arg_card, ApiResponse& response);
	bool UnbindCard(const std::string& arg_card, ApiResponse& response);
	bool LoginC(const std::string& arg_card, const std::string& arg_InvitationCode, const std::string& arg_VerifyCode, ApiResponse& response);
	bool RechargeC(const std::string& arg_card, const std::string& arg_RechargeCard, const std::string& arg_VerifyCode, ApiResponse& response);
	bool QueryAccount(const std::string& arg_Account, const std::string& arg_Password, ApiResponse& response);
	bool UnbindAccount(const std::string& arg_Account, const std::string& arg_Password, ApiResponse& response);
	bool LoginA(const std::string& arg_Account, const std::string& arg_Password, const std::string& arg_VerifyCode, ApiResponse& response);
	bool Register(const std::string& arg_Account, const std::string& arg_Password, const std::string& arg_Card, const std::string& arg_ContactInfo, const eum_ContactType& arg_ContactType, const std::string& arg_InvitationCode, const std::string& arg_VerifyCode, ApiResponse& response);
	bool ChangePasswordA(const std::string& arg_Account, const std::string& arg_NewPassword, const std::string& arg_ContactInfo, const eum_ContactType& arg_ContactType, const std::string& arg_VerifyCode, ApiResponse& response);
	bool RechargeA(const std::string& arg_Account, const std::string& arg_Password, const std::string& arg_RechargeCard, const std::string& arg_VerifyCode, ApiResponse& response);
	bool HeartBeat(ApiResponse& response);
	bool SubScore(int arg_score, ApiResponse& response);
	bool GetAntiVariableValue(const std::string& arg_VariableName, ApiResponse& response);
	bool GetAntiAlgorithmValue(const std::string& arg_AlgorithmName, const std::string& arg_ReqArguments, ApiResponse& response);
	bool GetSoftInfo(ApiResponse& response);
	bool GetConfig(ApiResponse& response);
	bool DownloadCloudFile(const std::string& fileIdentifier, const std::string& version,
		const std::string& requestId, ApiResponse& response);
	bool ListVersions(int page, int pageSize, ApiResponse& response);
	bool FeedbackList(int page, int pageSize, ApiResponse& response);
	bool EditConfig(const std::string& arg_Config, ApiResponse& response);
	bool ClearConfig(ApiResponse& response);
	bool GetVerifyCode(ApiResponse& response);
	bool GetVerifyCodeWithScene(const std::string& arg_CaptchaScene, ApiResponse& response);
	bool GetInviteHarvest(ApiResponse& response);
	bool GetInviteRecord(ApiResponse& response);
	bool GetTimeStamp(ApiResponse& response);
	bool Logout(ApiResponse& response);
	bool QueryOnlineDeviceC(const std::string& arg_card, ApiResponse& response);
	bool KickOnlineDeviceC(const std::string& arg_card, int arg_index, ApiResponse& response);
	bool QueryOnlineDeviceA(const std::string& arg_Account, const std::string& arg_Password, ApiResponse& response);
	bool KickOnlineDeviceA(const std::string& arg_Account, const std::string& arg_Password, int arg_index, ApiResponse& response);
	bool GetSvrNodes(ApiResponse& response);
	bool ChangeSvrNode(const std::string& arg_http_address, const std::string& arg_https_address, const std::string& arg_socket_address, const std::string& arg_ws_address, const std::string& arg_wss_address, ApiResponse& response);

	bool SendMessageZ(int arg_Msg_type, const std::string& arg_Msg_body, ApiResponse& response);
	bool SendMessageZWithVerifyCode(int arg_Msg_type, const std::string& arg_Msg_body,
		const std::string& arg_VerifyCode, ApiResponse& response,
		const std::string& arg_LogLevel = "", const std::string& arg_CustomType = "");
	bool FeedBack(const std::string& arg_Msg_body, ApiResponse& response);
	bool FeedBackWithVerifyCode(const std::string& arg_Msg_body, const std::string& arg_VerifyCode,
		ApiResponse& response);
	bool Log(const std::string& arg_Msg_body, ApiResponse& response);
	bool Log(const std::string& arg_Msg_body, const std::string& arg_LogLevel,
		const std::string& arg_CustomType, ApiResponse& response);
	bool TryIt(const std::string& arg_VerifyCode, ApiResponse& response);
	bool SignIn(ApiResponse& response);
	bool SignInFix(const std::string& arg_TimeStamp_s, ApiResponse& response);
	bool SignInQueryHistory(const std::string& arg_Page, const std::string& arg_PageSize, const std::string& arg_TimeOrder, ApiResponse& response);
	bool GradeQueryList(const std::string& arg_Page, const std::string& arg_PageSize, const std::string& arg_TimeOrder, ApiResponse& response);
	bool LotteryQueryList(ApiResponse& response);
	bool LotteryStart(const std::string& arg_Num, ApiResponse& response);
	bool LotteryQueryHistory(const std::string& arg_Page, const std::string& arg_PageSize, const std::string& arg_TimeOrder, ApiResponse& response);
	bool ShopQueryList(const std::string& arg_Page, const std::string& arg_PageSize, const std::string& arg_TimeOrder, ApiResponse& response);
	bool ShopBuy(const std::string& arg_Id, ApiResponse& response);
	bool ShopQueryHistory(const std::string& arg_Page, const std::string& arg_PageSize, const std::string& arg_TimeOrder, ApiResponse& response);

private:
	void extractIpAndPort(const std::string& input);
	bool DeserializeJson(const std::string& de_data, ApiResponse& response);
	std::string GetLocalTimestamp();
	std::string ToPackPostData(const std::string& json_data);
	std::string ToUnPackPostData(const std::string& json_data);
	std::string SendPostRequest(const std::string& apiUrl, const std::string& data);
	std::string GetSocketMsg(const std::string& response_json);
	std::string GetWebSocketMsg(const std::string& response_json);
	size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* response);

	std::string string_To_UTF8(const std::wstring& wstr);

	std::string UnicodeToUTF8(const std::wstring& wstr);

	std::wstring UTF8ToUnicode(const std::string& str);

	std::string UnicodeToANSI(const std::wstring& wstr);

	std::wstring ANSIToUnicode(const std::string& str);

	std::string UTF8ToANSI(const std::string& str);

	std::string ANSIToUTF8(const std::string& str);

	std::string escapeJson(const std::string& input);

	std::string escapeJSONSpecialChars(const std::string& str);


#pragma region 动态日期

	//SDK要与服务端保持一致
	std::string c_em_list_0 = "PFEv;Jr2~|d<LN!3&pD.WMTcgZ5^s/KSiuIn4,6'VkQqblB$j:Xo%Cf}{+(@)ax_=O9eY8U>0y#?hm1Aw*[zR-`7G]tH";
	std::string c_em_list_1 = "x*V,JG52`-KmIo|0qhsOeB}];wd7{+AgU:1<iR%$~_#3Fy!Pr'/6ack.=XM84)YHbjnpSl>^QN9Tf&Wt@Lv(?[CzDZEu";
	std::string c_em_list_2 = "hO%K;RgL]ePNpZn/)@:>f#oGjSX.A,1iW[6F}9&(D+k`d?wJ25msxv!$4Hybr8|-^I{z<_VMT7'UC0u3=Bc*lqtaEQY~";
	std::string c_em_list_3 = "%{'uJOvN=V>5kz1<q3bLn7H#:o~+i-lt*`j|a?!Y}UhWFTXQyR8/Ep(2S9wBdP$C_r,^s]04DZK.fG[c@6eMI)g&xmA;";
	std::string c_em_list_4 = "HyJ<eO@R_L^Nn:)>Ww*g1z+Zr&%$}8f#M'A.vF[!sCix74md|,;b0{9Gu5YlBqI]j~p(/-Pho3TD?2KUQk6t`XcVE=aS";
	std::string c_em_list_5 = ",>zMIXl#78-[$9Ybt+OLyUgu/j5C~);!<`Bvqk3*ZF1|'Se?ow=iRW@0J{PN:}ATEQfcD.(&V%]^nGHdh_x2sma46Kpr";
	std::string c_em_list_6 = "Z7(ydU1^5wzc&BqYV-4f%MEIv*l?m#}<~k9'$xTeusgp2j!{WC6`n,0Qa]8+OA[R:G3X)th_=P/HJS.@>;rbiLoFNDK|";
	std::string c_em_list_7 = "6e<?xS^*2nf+#c8X`5Cu[H&9G/N}=t!Lk]P:RrU(;ih_'WQz@$7b%wY3BA>|OMq4o~0IFZdEgyDTl1K-sJv{)aVm,pj.";
	std::string c_em_list_8 = "r^mPdesYt`lzCMQ@a/qh[-Z.28EN?9VH)B;_iS0}<nLfOwJkU7j$G3pc:o{~|+xy(56gT4='W#*Ru&!KAXIDv>]F%1,b";
	std::string c_em_list_9 = "[n31wa7bo:QBDsi!A'|y>$~tL,-IhuOZ`@MjdUHrkYc5Kg<=0G/9RzW8&2%4xJN*}CmVE;6q{lF]_X^+eTP?v)f.#S(p";
	std::string c_em_list_10 = "9[I-cmg]anV^fX:BdPZk>o0(42$jy6%SEYi}<qQ'W5b+);=CGDM8O!&@~w_z,p3A{FhUu|?1sv/JNlx*`#rKRLH7teT.";
	std::string c_em_list_11 = "CwaTzlx}ZeDVi7HAFM*3JhboR:yg?1@vU$G&-><|n5su=P94Q)B`+]S/{k(6.~mNYpW#_2Ef'K^OX!qL,d%cj[8r;I0t";
	std::string c_em_list_12 = "jUr6)i#:WR[$e<YA(CM^QV>.@NXTmnx9?f{K}J81lP;4usyDI,!&0oO_w=Lqc`*ka~7F%|-B]Ehbpt+g2vz5HZ3'/GSd";
	std::string c_em_list_13 = "U5>+wrkjJ&|m8%)eFbyxP,qOR=IuzoD94:V61XAtB]0Q_7ZYdf<3-GnvWTKlp~!$c(?NC;HLaS'^#Mhs@g/2`E{*i[}.";
	std::string c_em_list_14 = "1cLW(r3oH9@.8E?g=V`&b[P)*I|k,e>+FQ#^ZT!S/u-z%RONlt;da2}~i:4GB67CvjY5sx0mMJwKfA'q$y{UX]D_hnp<";
	std::string c_em_list_15 = "<Bd8`p&qHynk9gPfxOm.r)|cai7ZeS}EGIz:3#>(A@;M+RWvNsw,6Q'/l[F~L1T%hV^=4*-${tDbuX]0K_!CJ2oYU5j?";
	std::string c_em_list_16 = ")l_}^xp~,GrK/Q7@=m-#hig0(Bt2oXdA>%UW9E5Hnj?w3!`:s8DTyCIONb$LeS<[{|+ckvVa1F&Yzq6P4R]MZ'f*.Ju;";
	std::string c_em_list_17 = "MJ`a?y7B:/b3.s[@whV'vfKRjdYz|QeT{StHC}~WNDL_gU->ZqA&,x^n#i8*=XrIp6%O0lF]1c!$E295G;ok<4)+uP(m";
	std::string c_em_list_18 = "?uqr*7fy)tbaVZhG|#9(zC8l}/N[EW{OjcI`~;g,XmkA61+!eB_R-^HP5M=w.>JS2:F$K]s4%'DoLiQp@U3Tnd<0x&vY";
	std::string c_em_list_19 = "eS8:?5vz&jK=X4yF13H<@/fBkW,*pO(hYlxV|Nbd%;9{cQ_oZA't0UG^sCMi`u}IqD-mgT6Lr#nP27$R.J~)Ew+[>a!]";
	std::string c_em_list_20 = "@:[bR3#0%a,ZW/(FdutL_;E1`v85|C4xSm6HMi~cBQPp=e?nDwhY}IU]fkA*{o.&!GzKsq^Vljr+y9g2O<XJ$)NT>-7'";
	std::string c_em_list_21 = "wbdu?^mK2]/B1(Wn5+,<*xz[jPy.DJRt&4:7)pkT|QFUA`H{=el%}X0girhZ_S~3!;->9vo6I8s$Ea@ML'qYNfcOCG#V";
	std::string c_em_list_22 = ";~t'R@0Mx^&rzGnjc*eL.sZmBud}pAJ-$!bH:?4=W%6)Sw[7#D/qYh(v1aUC8|FP`+VIK<2E9Ti53Xfl]g>y{,kQ_OoN";
	std::string c_em_list_23 = "W@!em$)Ox6w~0j9kF8+bDlAC2[K=',B`TaJzfUuHG}S?^;RXP>d{(.34g:soZLNIqMEtpn/|c%7&Y]-*h#5_i<y1vrQV";
	std::string c_em_list_24 = "HJRyT=t$kQ4^'VP_j?WMCK1dEr~GB/2.N0(n!p[q<5vc@&%D]-emSw8a{h;`7u}#X*,U)OYflF:gI>iLxosb3A+|Z96z";
	std::string c_em_list_25 = "o-g>l(6$fFhR:xe)I;5bNBW}4%&`p{qM@JX~KOyQGzPc.H/^*=iaw8n_m,Z[+2|v#sDSA?7Y9C3U'uktrV1<jTL0E]d!";
	std::string c_em_list_26 = "ZQ]NS:jYW4q,Th}LoPDMR^-HIp!g6/~JC;vXFmO`$?)9Vn.d[B5a=3f{Atw1e*kx|82>_s+7iU&@r<'l0(zc%bGKEu#y";
	std::string c_em_list_27 = "6;Czl}wYStTkR@GMLJvid!y&%$nUA|.fW8pg7Pe1mQNo`_9*>rX-?E5B:^#Fuh=2,O<a+3I~jbVK]xH'DZ)sc4({q/[0";
	std::string c_em_list_28 = "~0S?5]@bPkA;T`YL+C:wmyRcW.NIq%-x}nfX74*F_</KJ&)p8|aeB(UOv2zjZQ,>o!h^#Ht9lr=31G{$V'MuiEgD[ds6";
	std::string c_em_list_29 = "[?!Qk>m=D,F1u(^rOcbfjU$w@2Ei0+ds8p{al.GZTI'Y%3XM9:o~W<Pzg-S#Lq`5vCt_H})&AyNeJ7*|]VB/64;hRnKx";
	std::string c_em_list_30 = "R!;25>0{B+[IsL?p|W%urOkJZ:)c~7V96K'q`-]dHa(1e@AmfS&},N<vn/UwY$#zyojECPM.hQF=G^T8liXg*tD3bx4_";
	std::string c_em_list_31 = "yhFB}.*;A$40tmPr5QS&8JN#]TzXl1O<|%e:RD_>{9+HZE!kbIp@u^xnU[if?sL2M3q'Kvj/=aG)Vw6Wgocd7CY,~(-`";
	std::string c_em_list_32 = "j(yT6Dsl}X@b]V9|.p1w7)8>Y+mrv4$;'*o,3ZI`N[%h_Gf!R0HKt-5AW2B?L~^enC:xagU=&#JOik<zMcP{FdSuEQq/";
	std::string c_em_list_33 = "&q%5{B7m]Op-+x;[2eC$*8ds'JSj`tzGb^yQw@Ncl)0KR(#ahY6<AnP}vHFMk=|3_oL4i/VDf~!1rgZ9:>IU?XTW.uE,";
	std::string c_em_list_34 = "1}T[4Li/@!trKgfS>#my(e'*b)H%I2MBXn{?F8Gw]qC09jW:VA$c~Z3<.;QvU|6sO`_^u&EpJ75,zdhoRlaxN-+kYP=D";
	std::string c_em_list_35 = "<yjW]Jx~92b`L@wR!3{&;Z0e'D[4roCTSu,adE)gUiOt5Y6K}_F|8cV71zG#AsnQ*Nm(./XlM>=f$IkPHqB-h+?^vp:%";
	std::string c_em_list_36 = "bX2!GI^B8uKtOC_Vnze>DYi/wk@4?m<rWS}{F`,gM(3#6pfL[sNo]9&'+1=Zy~%h7HT.0;-)cqPUJalRQvx$|A*:jd5E";
	std::string c_em_list_37 = "M8G|]ToyuCPUq[a2%+#*A.}R/~t=Jnriw&;'_Zgh$1@:pEc?WYFVH3NbsLv`{lf5!z>BmS4d0(xDe<O9,^jIk7Q-X6K)";
	std::string c_em_list_38 = "tfWZFQ52u.<#oMr0m(K>L[z-waY)xgj8ND*;ET$X`7~?HB&yn9,v_ic%SR']@!6^pICb4}Vq|l{sU=G/31Pe:OAJdhk+";
	std::string c_em_list_39 = "{Do@aP)2r[%Qns8yM9zLX-YhG3C^>Vd;5?w~*pbv:W+uSH]6!gEct#/Il.74BN&(iF<'1fO|e`RJ_Z$U=mKxAjT}k,q0";
	std::string c_em_list_40 = "@o,;FYtLeh)|&XO.r?/<Vm*1xR:`Gb_%cKJ$EU9{}I#+n2aNS5lszQ>83Tvdyi]~g!C6-pf4wqj0ZDBP7u'MW^=k(H[A";
	std::string c_em_list_41 = "ENKecZ!Pga2n-6l,S:pMokyTJ1&'xU_A/i0G`7]s[={R|%L<(3vDB4+@?*8;$).#rzF9Qmf}b^HIhYOVqu>tdWwj5X~C";
	std::string c_em_list_42 = ";x2tFgi@O_5IGl|ZuR+/hCDp6Q7T#bc?U~JsH!{y(z.)BNY9>e}W]$A*d=S04w%qKXn'M`[,VmaE1jP&v^fk:3r8o-L<";
	std::string c_em_list_43 = "WV).ahz#L@l2F&EZTJYOw?(BRtkKGUcX`4}%i5I>]{'fduH~16sQD_$:PbA<^N[y/,8=qxv|ge!+jMr9n;-om*Cp3S07";
	std::string c_em_list_44 = "3./etc$%J0QFGEZa<B@i6;p5*(LAsIOmT,Wlgb[H'Vfkoduv=n}|{8X9YMNwr1>_2-:Sxjz]y7)RK!&~?D+4UC`#Pq^h";
	std::string c_em_list_45 = "oepzYqnV?KU_j}(7TdGM83`{QlAc9L@ht&C2B5P,$b6|HOvg;ZmaJ^#Nf1I!sW*)ERur4%+0w>[xF=S<kX]:'-y/.D~i";
	std::string c_em_list_46 = "_C5/tl3Y<BEajR>6`Wwg&u@o)!*QFDyz^;4#]GvqVHUM0Z+kNp18'A|xr[eTh(27cSO9nXLK~$}?mf:,PI=s-d.Jb{i%";
	std::string c_em_list_47 = "O%=i$k)b<,_&gsM29N/v}jeCa`tJp:o^L'V>yPXq0mWz7?*G4{8RZ-3;(fur6+|FU!1Y5]xShnIwlAT.~BK@DQHEd#[c";
	std::string c_em_list_48 = "~Lb1tvs[-n}p@Z8?Amed|I,V)4jk3`/#&rx6KUzOo+=0hg<2(GY;cyP$'^5u!XW_CiaFf7DEN%l*H:JS9QwqT{M.]BR>";
	std::string c_em_list_49 = "g+r~$s8}*d5/91]>@c(q`By[a:LXC{|'G=eNSpfkjQb&UO<.3YK2A_!H%luIh,;W#6JVzPEZ0Mi-Dx^Tvo)?m4wFtn7R";
	std::string c_em_list_50 = "RU/Su4kj7;$!~nedC#Pg?^MI]zF5O<p}V>'qyt:m+AG&B)_f=9L8{%cW|1a(l6Nvo.`rJ[w3QX*2,KbYxEZhT0Hs-i@D";
	std::string c_em_list_51 = "y,N4%0xj3_qO~(vb)26sH7|@g{[pu]YF5Kt+DA.G}Zi;Sr*19Mln&Xc8eEz`fQCP'Rma$J?Lowk#d!UI/V-<hWT:=^>B";
	std::string c_em_list_52 = "'3dC<z%n0!X8~H*cruF(TxyY?M1mA&VbkeE`Ppv/R{N.fw-)Ot2,l69U@Q$g^ZKq4+]GSsh7L:;IW_5ji#B=>a[}|DoJ";
	std::string c_em_list_53 = "&A+V#8o/mSdib:W@_[ryRTIwq-t*L])X?F`OKEGgUu;0h54^pB=c({eY!s,}v7%96NPCj>Q$f.aM~lnxJ3'k<ZD2zH1|";
	std::string c_em_list_54 = "J$~6.72`jKL]bTp!u&;^eO_HBGW8y@9oPNAX53Cx(<Y{%4s)i-?t=IqQa:dnlSvD}0#|cmV*z1UgMZ,fw/ErRh'F>[+k";
	std::string c_em_list_55 = "qkQFP8_BmC,hd0@$X!f>uJx&4i`2~15%+o-wr^Y/]WMy9Azb(s3Z'}IV7.TEg?6GOKS{=RenN[jLHap*t#v<cl:)UD;|";
	std::string c_em_list_56 = "b_9W<&txVy/F4eMDz?^*o)E,HB|{O6P5Q]2mn>8=Sa#$Ni:7uvl%YZ@Ir}1~!XA;(hCdR.gKTUp+jLJqkw30[s'-`cfG";
	std::string c_em_list_57 = "8t{9N^!yUn*x37dDY'O>0$)r2Z4+sqC;uJ(e&GPQpS#F/1|%=wVvzj@cT.i[-K`<X6LAR}M]HmgIW_5hkbBElo:~?af,";
	std::string c_em_list_58 = "t:e}.=jIH`(X,p+k0Pz$1fW&G/vF94y-'[;%BwOQmC?~V2h8gS)U<McNJsLD_d5Eol7quY|!n*RA3Z>{T]ri6#^K@axb";
	std::string c_em_list_59 = "{1uZN+zKF;2*<)EjcJA/#d~h8Wb`MvsCSaoI|t^k-xB]3w6iyl>RfnO5.VLmD'gPG[}4Tp_?:!XY$q&HUQ07(=e9%@r,";

#pragma endregion

	int findPostMethod(int post_method, const std::string& c_em_list);

	/// <summary>
	/// 计算出请求的方法ID
	/// </summary>
	/// <param name="postTimes"></param>
	/// <param name="postMethod"></param>
	/// <returns></returns>
	int CalcPostMethod(long long postTimes, int postMethod);

	/// <summary>
	/// 匿名写入请求
	/// </summary>
	/// <param name="requestData"></param>
	/// <param name="time"></param>
	/// <returns></returns>
	bool ToWrite(std::string requestData, std::string time, ApiResponse& response);

	std::string ReplaceMethodValue(const std::string& jsonData, const std::string& newMethod);

	bool ToMoreWrite(const std::string& requestData, const std::string& time, ApiResponse& response);
};
