#pragma once
#include <string>
#include <map>
#include <regex>
#include <initializer_list>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>
#include <fstream>

namespace wrap {

struct Comparator {
    bool operator() (const std::string& s1, const std::string& s2) const {
        std::string str1, str2;
        for (auto& c : s1) str1 += std::tolower(c);
        for (auto& c : s2) str2 += std::tolower(c);
        return str1 < str2;
    }
};

struct Body {
    std::string body;
};

struct File {
    std::string file;
};

struct Download {
    std::string dl = "dl";
};

struct Method {
    std::string method;
};

struct Url {
    std::string adr;
};

struct UserAgent {
    std::string usr;
};

struct Header {
    std::map<std::string, std::string> hdr;
    Header(std::initializer_list<std::pair<const std::string, std::string> > hdr) : hdr(hdr) {}
};

struct Parameters {
    std::map<std::string, std::string> p;
    Parameters(std::initializer_list<std::pair<const std::string, std::string> > p) : p(p) {}
};

struct Cookies {
    std::map<std::string, std::string> c;
    Cookies(std::initializer_list<std::pair<const std::string, std::string> > c) : c(c) {}
};

struct Payload {
    std::map<std::string, std::string> pd;
    Payload(std::initializer_list<std::pair<const std::string, std::string> > pd) : pd(pd) {}
};

struct Multipart {
    std::map<std::string, std::string> mp;
    Multipart(std::initializer_list<std::pair<const std::string, std::string> > mp) : mp(mp) {}
};

struct Authentication {
    std::string usr;
    std::string pwd;
};

struct Bearer {
    std::string token;
};

struct Timeout {
    unsigned long timeout;
    std::string type = "request";
};

struct Options {
    std::map<std::string, std::string> options;
    Options(std::initializer_list<std::pair<const std::string, std::string> > options) : options(options) {}
};

struct Proxy {
    std::string url;
    std::string usr = "";
    std::string pwd = "";
};

struct req {
    std::string ua = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0";
    std::string Params;
    std::string PostData;
    std::string Dl;
    std::string Method = "GET";
    std::string Auth;
    std::string Url = "www.example.com";
    wrap::Proxy Proxy;
    std::map<std::string, std::string> cookies_tosend;
    bool cookie_encode = true;
    bool redirect = true;
    bool newsession = true;
    Header Header = { {"",""} };
    unsigned long TimeoutConnect = 0;
    unsigned long TimeoutRequest = 0;
    void reset() {
        ua = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0";
        Params = "";
        PostData = "";
        Dl = "";
        Method = "GET";
        Auth = "";
        Url = "www.example.com";
        Header = { {"",""} };
        // 超时字段保留不重置：由 ZoneHelperCore 构造时统一设置（防网络黑洞卡死心跳线程）
        // TimeoutConnect = 0;
        // TimeoutRequest = 0;
        newsession = false;
        cookie_encode = true;
        redirect = true;
    };
};

struct Response {
    std::map<std::string, std::string, Comparator> header;
    std::map<std::string, std::string> sent_headers;
    std::map<std::string, std::string> secinfo;
    std::map<std::string, std::string> cookies;
    std::string url;
    std::string raw;
    std::string text;
    std::string status_code;
    std::string err;
    unsigned long uploaded_bytes = 0;
    unsigned long downloaded_bytes = 0;
    unsigned long redirect_count = 0;
};

std::string text_from_html(std::string html);

extern req toSource;

void Params(wrap::Parameters s);
void Params(wrap::Url u);
void Params(wrap::UserAgent usr);
void Params(wrap::Header h);
void Params(wrap::Payload pd);
void Params(wrap::Multipart mp);
void Params(wrap::Authentication auth);
void Params(wrap::Bearer token);
void Params(wrap::Method m);
void Params(wrap::Download dl);
void Params(wrap::Body body);
void Params(wrap::Cookies c);
void Params(wrap::File file);
void Params(wrap::Timeout timeout);
void Params(wrap::Options options);
void Params(wrap::Proxy proxy);

Response httpsreq(req Request);

template <typename ...Ts>
Response HttpsRequest(Ts&& ...args) {
    std::initializer_list<int> ignore = { (Params(args), 0)... };
    (void)ignore;
    return httpsreq(toSource);
}

}
