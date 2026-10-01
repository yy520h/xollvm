#include "wnetwrap.h"
#include <curl/curl.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/syscall.h>
wrap::req wrap::toSource;

static inline void ltrim(std::string& s);
static inline void rtrim(std::string& s);
static inline void trim(std::string& s);
std::string GetMimeType(const std::string& ext);
std::string url_encode(std::string const& str);
std::string hex_encode(char const c);
static std::string base64_encode(const std::string& in);

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

static size_t HeaderCallback(char* buffer, size_t size, size_t nitems, std::map<std::string, std::string>* headers) {
    std::string line(buffer, size * nitems);
    size_t pos = line.find(':');
    if (pos != std::string::npos) {
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        size_t start = value.find_first_not_of(" \t\r\n");
        size_t end = value.find_last_not_of(" \t\r\n");
        if (start != std::string::npos) {
            value = value.substr(start, end - start + 1);
        }
        for (auto& c : key) c = std::tolower(c);
        (*headers)[key] = value;
    }
    return size * nitems;
}

static inline std::map<std::string, std::string> handleURI(wrap::req& request, wrap::Response& output, int& port) {
    std::map<std::string, std::string> URI;
    URI["host"], URI["path"], URI["scheme"], URI["urlfile"] = "";
    URI["host"] = request.Url;
    if (URI["host"].find("://") != std::string::npos) {
        URI["scheme"] = URI["host"].substr(0, URI["host"].find(":"));
        URI["host"] = URI["host"].substr(URI["host"].find("://") + 3);
    }
    else {
        URI["scheme"] = "https";
    }

    if (URI["scheme"] == "https") {
        port = 443;
    }
    else if (URI["scheme"] == "http") {
        port = 80;
    }
    else {
        output.err = "Error: URL input has scheme other than HTTP/S";
    }

    if ((URI["host"].find("/") != std::string::npos) || (URI["host"].find("?") != std::string::npos)) {
        if ((URI["host"].back() != '?') && (URI["host"].back() != '/')) {
            if (URI["host"].find("/") != std::string::npos) {
                URI["path"] = URI["host"].substr(URI["host"].find("/"));
                URI["host"] = URI["host"].substr(0, URI["host"].find("/"));
            }
            else {
                URI["path"] = URI["host"].substr(URI["host"].find("?"));
                URI["host"] = URI["host"].substr(0, URI["host"].find("?"));
            }
            if (URI["path"].find_last_of("/") != std::string::npos) {
                if (URI["path"].substr(URI["path"].find_last_of("/") + 1).find(".") != std::string::npos) {
                    URI["urlfile"] = URI["path"].substr(URI["path"].find_last_of("/") + 1);
                }
            }
            else {
                if (URI["path"].find_last_of("?") != std::string::npos) {
                    if (URI["path"].substr(URI["path"].find_last_of("?") + 1).find(".") != std::string::npos) {
                        URI["urlfile"] = URI["path"].substr(URI["path"].find_last_of("?") + 1);
                    }
                }
            }
        }
        else {
            URI["host"] = URI["host"].substr(0, URI["host"].size() - 1);
        }
    }

    if (request.Params != "") {
        URI["path"] += request.Params;
    }

    output.url = URI["scheme"] + "://" + URI["host"] + URI["path"];

    if (request.Dl == "dl") {
        request.Dl = URI["urlfile"];
    }

    return URI;
}

static inline void prepare_cookies() {
    std::string cookiehdr = "";
    int ecount = 0;
    for (auto elem : wrap::toSource.cookies_tosend) {
        ecount++;
        if (wrap::toSource.cookie_encode) {
            cookiehdr += url_encode(elem.first) + "=" + url_encode(elem.second);
        }
        else {
            cookiehdr += elem.first + "=" + elem.second;
        }
        if (ecount != wrap::toSource.cookies_tosend.size()) {
            cookiehdr += "; ";
        }
    }
    if (!cookiehdr.empty()) {
        wrap::toSource.Header.hdr.insert(std::pair<std::string, std::string>("Cookie", cookiehdr));
    }
    wrap::toSource.cookies_tosend.clear();
}

static inline std::string prepare_headers(wrap::req& request) {
    prepare_cookies();
    if (request.Method == "POST") {
        if ((request.Header.hdr.find("content-type") == request.Header.hdr.end()) &&
            (request.Header.hdr.find("Content-Type") == request.Header.hdr.end())) {
            request.Header.hdr.insert(std::pair<std::string, std::string>("Content-Type", "application/x-www-form-urlencoded"));
        }
    }
    if (request.Method == "GET") {
        if ((request.Header.hdr.find("content-type") == request.Header.hdr.end()) &&
            (request.Header.hdr.find("Content-Type") == request.Header.hdr.end())) {
            request.Header.hdr.insert(std::pair<std::string, std::string>("Content-Type", "text/plain"));
        }
    }

    std::string final_headers = "";
    for (auto elem : request.Header.hdr) {
        if (elem.first != "") {
            final_headers += elem.first + ":" + elem.second + "\r\n";
        }
    }
    if (final_headers != "") {
        final_headers += "\r\n\r\n";
    }
    return final_headers;
}

wrap::Response wrap::httpsreq(wrap::req request) {
    wrap::Response output;
    int port = 443;
    std::map<std::string, std::string> URI = handleURI(request, output, port);

    CURL* curl = curl_easy_init();
    if (!curl) {
        output.err = "curl_easy_init failed";
        return output;
    }

    std::string full_url = URI["scheme"] + "://" + URI["host"];
    if (!URI["path"].empty()) {
        full_url += URI["path"];
    }
    else {
        full_url += "/";
    }

    curl_easy_setopt(curl, CURLOPT_URL, full_url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, request.Method.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, request.ua.c_str());
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");  // 加这行：自动处理 gzip/deflate

    if (!request.Proxy.url.empty()) {
        curl_easy_setopt(curl, CURLOPT_PROXY, request.Proxy.url.c_str());
        if (!request.Proxy.usr.empty()) {
            curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, request.Proxy.usr.c_str());
            curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, request.Proxy.pwd.c_str());
        }
    }

    struct curl_slist* headers = NULL;
    for (auto elem : request.Header.hdr) {
        if (!elem.first.empty()) {
            std::string h = elem.first + ": " + elem.second;
            headers = curl_slist_append(headers, h.c_str());
        }
    }
    if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    if (!request.PostData.empty()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.PostData.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)request.PostData.size());
    }

    if (request.TimeoutConnect > 0) {
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, (long)request.TimeoutConnect);
    }
    if (request.TimeoutRequest > 0) {
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)request.TimeoutRequest);
        // 第二道防线：传输阶段持续 8s 无数据流动即断（防服务器慢流拖死）。
        // TIMEOUT_MS 是硬总超时，但对"每 7s 挤一个字节"的慢流无能为力，LOW_SPEED 补位。
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 8L);
    }
    else if (request.TimeoutConnect > 0) {
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)request.TimeoutConnect);
    }

    if (request.redirect) {
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);
    }

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

std::string response_body;
std::map<std::string, std::string, wrap::Comparator> recd_headers;
curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
curl_easy_setopt(curl, CURLOPT_HEADERDATA, &recd_headers);

FILE* pfile = nullptr;
if (!request.Dl.empty()) {
    pfile = fopen(request.Dl.c_str(), "wb");
    if (pfile) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, pfile);
    }
}
else {
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
}


    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        output.err = std::string("curl_easy_perform failed: ") + curl_easy_strerror(res);
        if (pfile) fclose(pfile);
        if (headers) curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        wrap::toSource.reset();
        return output;
    }

    long status_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    output.status_code = std::to_string(status_code);

    long redirect_count = 0;
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &redirect_count);
    output.redirect_count = static_cast<unsigned long>(redirect_count);

    double downloaded = 0;
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &downloaded);
    output.downloaded_bytes = static_cast<unsigned long>(downloaded);

    char* final_url = nullptr;
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &final_url);
    if (final_url) {
        output.url = final_url;
    }

    output.header = recd_headers;

    for (auto& h : recd_headers) {
        if (h.first == "set-cookie") {
            std::string value = h.second;
            std::string cname = value.substr(0, value.find("="));
            std::string cvalue = "";
            if (value.find("=") != std::string::npos) {
                cvalue = value.substr(value.find("=") + 1);
                if (cvalue.find(";") != std::string::npos) {
                    cvalue = cvalue.substr(0, cvalue.find(";"));
                }
            }
            output.cookies[cname] = cvalue;
        }
    }

    if (!request.Dl.empty()) {
        if (pfile) {
            fflush(pfile);
            fclose(pfile);
        }
    }
    else {
        output.raw = response_body;
        std::string doctype = response_body.substr(0, 14);
        for (auto& c : doctype) c = std::tolower(c);
        if (doctype == "<!doctype html") {
            output.text = wrap::text_from_html(response_body);
        }
        else {
            output.text = output.raw;
        }
    }

    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    wrap::toSource.reset();
    return output;
}

std::string wrap::text_from_html(std::string html) {
    std::string output = "";
    bool over_tag = false;
    bool js = false;
    bool css = false;
    for (std::string::size_type i = 0; i < html.size(); ++i) {
        if (html[i] == '<') {
            if (html[i + 1] == '/') {
                if (html.substr(i + 2, 5) == "style") {
                    css = false;
                }
                if (html.substr(i + 2, 6) == "script") {
                    js = false;
                }
            }
            else {
                if (html.substr(i + 1, 5) == "style") {
                    css = true;
                }
                if (html.substr(i + 1, 6) == "script") {
                    js = true;
                }
            }
            over_tag = true;
        }
        if ((!js) && (!css) && (!over_tag)) {
            output = output + (html[i]);
        }
        if (html[i] == '>') {
            over_tag = false;
        }
    }
    return output;
}

static inline void ltrim(std::string& s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
        return !std::isspace(ch);
    }));
}

static inline void rtrim(std::string& s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

static inline void trim(std::string& s) {
    ltrim(s);
    rtrim(s);
}

std::string GetMimeType(const std::string& ext) {
    static const std::map<std::string, std::string> mime = {
        {".jpg", "image/jpeg"}, {".jpeg", "image/jpeg"},
        {".png", "image/png"}, {".gif", "image/gif"},
        {".bmp", "image/bmp"}, {".ico", "image/x-icon"},
        {".svg", "image/svg+xml"}, {".webp", "image/webp"},
        {".txt", "text/plain"}, {".html", "text/html"},
        {".htm", "text/html"}, {".css", "text/css"},
        {".js", "application/javascript"}, {".json", "application/json"},
        {".xml", "application/xml"}, {".zip", "application/zip"},
        {".gz", "application/gzip"}, {".tar", "application/x-tar"},
        {".pdf", "application/pdf"}, {".mp3", "audio/mpeg"},
        {".mp4", "video/mp4"}, {".webm", "video/webm"},
        {".ogg", "audio/ogg"}, {".wav", "audio/wav"},
        {".woff", "font/woff"}, {".woff2", "font/woff2"},
        {".ttf", "font/ttf"}, {".otf", "font/otf"},
    };
    auto it = mime.find(ext);
    if (it != mime.end()) return it->second;
    return "application/octet-stream";
}

std::string hex_encode(char const c) {
    char s[3];
    if (c & 0x80) {
        std::snprintf(&s[0], 3, "%02X", static_cast<unsigned int>(c & 0xff));
    }
    else {
        std::snprintf(&s[0], 3, "%02X", static_cast<unsigned int>(c));
    }
    return std::string(s);
}

std::string url_encode(std::string const& str) {
    std::string res;
    res.reserve(str.size());
    bool form = true;
    for (auto const& e : str) {
        if (e == ' ' && form) {
            res += "+";
        }
        else if (std::isalnum(static_cast<unsigned char>(e)) ||
            e == '-' || e == '_' || e == '.' || e == '~') {
            res += e;
        }
        else {
            res += "%" + hex_encode(e);
        }
    }
    return res;
}

static std::string base64_encode(const std::string& in) {
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

void wrap::Params(wrap::Parameters p) {
    std::string final_params = "";
    int pcount = 0;
    for (auto elem : p.p) {
        pcount++;
        if (elem.first != "") {
            if (pcount > 1) {
                final_params += "&";
            }
            final_params += url_encode(elem.first) + "=" + url_encode(elem.second);
        }
    }
    wrap::toSource.Params = "?" + final_params;
}

void wrap::Params(wrap::Url u) {
    wrap::toSource.Url = u.adr;
}

void wrap::Params(wrap::Proxy p) {
    wrap::toSource.Proxy = p;
    wrap::toSource.newsession = true;
}

void wrap::Params(wrap::UserAgent usr) {
    wrap::toSource.ua = usr.usr;
    wrap::toSource.newsession = true;
}

void wrap::Params(wrap::Options o) {
    for (auto elem : o.options) {
        if ((elem.first.find("encod") != std::string::npos) && (elem.first.find("cookie") != std::string::npos)) {
            if ((elem.second.find("off") != std::string::npos) || (elem.second.find("false") != std::string::npos)) {
                wrap::toSource.cookie_encode = false;
            }
            if ((elem.second.find("on") != std::string::npos) || (elem.second.find("true") != std::string::npos)) {
                wrap::toSource.cookie_encode = true;
            }
        }
        if (elem.first.find("redirect") != std::string::npos) {
            if ((elem.second.find("off") != std::string::npos) || (elem.second.find("false") != std::string::npos)) {
                wrap::toSource.redirect = false;
            }
            if ((elem.second.find("on") != std::string::npos) || (elem.second.find("true") != std::string::npos)) {
                wrap::toSource.redirect = true;
            }
        }
    }
}

void wrap::Params(wrap::Header h) {
    wrap::toSource.Header = h;
}

void wrap::Params(wrap::Cookies c) {
    wrap::toSource.cookies_tosend = c.c;
}

void wrap::Params(wrap::Method m) {
    wrap::toSource.Method = m.method;
}

void wrap::Params(wrap::Download dl) {
    wrap::toSource.Dl = dl.dl;
}

void wrap::Params(wrap::File f) {
    std::string fname = f.file;
    if (std::ifstream inputstream{ fname, std::ios::binary | std::ios::ate }) {
        auto fsize = inputstream.tellg();
        std::string finput(fsize, '\0');
        inputstream.seekg(0);
        if (inputstream.read(&finput[0], fsize))
            std::cout << finput << '\n';
        wrap::toSource.PostData = finput;
    }
}

void wrap::Params(wrap::Body b) {
    wrap::toSource.PostData = b.body;
}

void wrap::Params(wrap::Payload pd) {
    std::string final_postdata = "";
    int pcount = 0;
    for (auto elem : pd.pd) {
        pcount++;
        if (elem.first != "") {
            if (pcount > 1) {
                final_postdata += "&";
            }
            final_postdata += url_encode(elem.first) + "=" + url_encode(elem.second);
        }
    }
    wrap::toSource.PostData = final_postdata;
}

void wrap::Params(wrap::Multipart mp) {
    std::string final_postdata = "";
    std::string boundary = "735323031399963166993862150";
    wrap::toSource.Header.hdr["content-type"] = "multipart/form-data; boundary=" + boundary;
    std::string fname, ctype;
    int pcount = 0;
    for (auto elem : mp.mp) {
        pcount++;

        if (elem.first.substr(0, 5) != "file:") {
            final_postdata += "--" + boundary + "\r\n";
            final_postdata += "Content-Disposition: form-data; name=\"" + (elem.first) + "\"\r\n";
            final_postdata += "Content-Type: text/plain\r\n\r\n";
            final_postdata += (elem.second) + "\r\n";
        }
        else {
            fname = elem.second.substr(elem.second.find_last_of("/\\") + 1);
            ctype = "application/octet-stream";

            if (fname.find_last_of(".") != std::string::npos) {
                std::string extension = fname.substr(fname.find_last_of("."));
                if (GetMimeType(extension) != "application/octet-stream") {
                    ctype = GetMimeType(extension);
                }
            }

            final_postdata += "--" + boundary + "\r\n";
            final_postdata += "Content-Disposition: form-data; name=\"" + (elem.first.substr(5)) + "\"; filename=\"" + fname + "\"\r\n";
            final_postdata += "Content-Type: " + ctype + "\r\n\r\n";

            if (std::ifstream inputstream{ elem.second, std::ios::binary | std::ios::ate }) {
                auto fsize = inputstream.tellg();
                std::string finput(fsize, '\0');
                inputstream.seekg(0);
                inputstream.read(&finput[0], fsize);
                final_postdata += finput + "\r\n";
            }
        }

        if (pcount == mp.mp.size()) {
            final_postdata += "--" + boundary + "--";
        }
    }
    wrap::toSource.PostData = final_postdata;
}

void wrap::Params(wrap::Authentication auth) {
    std::string basicauth = auth.usr + ":" + auth.pwd;
    basicauth = base64_encode(basicauth);
    wrap::toSource.Header.hdr["Authorization"] = "Basic " + basicauth;
}

void wrap::Params(wrap::Bearer token) {
    wrap::toSource.Header.hdr["Authorization"] = "Bearer " + token.token;
}

void wrap::Params(wrap::Timeout timeout) {
    if (timeout.type == "connection" || timeout.type == "all") {
        wrap::toSource.TimeoutConnect = timeout.timeout;
    }
    if (timeout.type == "request" || timeout.type == "all") {
        wrap::toSource.TimeoutRequest = timeout.timeout;
    }
}
