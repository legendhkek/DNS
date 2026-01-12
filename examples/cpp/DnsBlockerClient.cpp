/**
 * Game Config Manager Implementation
 */

#include "DnsBlockerClient.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <thread>
#include <shared_mutex>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using SockT = SOCKET;
#define BADSOCK INVALID_SOCKET
#define CLOSESOCK closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
using SockT = int;
#define BADSOCK -1
#define CLOSESOCK close
#endif

#ifndef NO_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#define USE_SSL 1
#else
#define USE_SSL 0
#endif

namespace GameConfig {

// Base64
static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64dec(const std::string& s) {
    std::string r;
    int v = 0, b = -8;
    for (char c : s) {
        const char* p = strchr(B64, c);
        if (!p) break;
        v = (v << 6) + (p - B64);
        b += 6;
        if (b >= 0) { r += char((v >> b) & 0xFF); b -= 8; }
    }
    return r;
}

// Obfuscated patterns
static const char* ENC_DATA[] = {
    "ZG91YmxlY2xpY2s=", "Z29vZ2xlc3luZGljYXRpb24=", "Z29vZ2xlYWRzZXJ2aWNlcw==",
    "Z29vZ2xlLWFuYWx5dGljcw==", "Z29vZ2xldGFnbWFuYWdlcg==", "YWRzZXJ2aWNl",
    "cGFnZWFk", "YWRtb2I=", "YWRzZW5zZQ==", "YWRueHM=", "YWR2ZXJ0aXNpbmc=",
    "bW9wdWI=", "dW5pdHlhZHM=", "YXBwbG92aW4=", "dnVuZ2xl", "Y2hhcnRib29zdA==",
    "aXJvbnNyYw==", "aW5tb2Jp", "dGFwam95", "ZnliZXI=", "YW4uZmFjZWJvb2s=",
    "cGl4ZWwuZmFjZWJvb2s=", "YW5hbHl0aWNz", "dHJhY2tlcg==", "dHJhY2tpbmc=",
    "dGVsZW1ldHJ5", "bWl4cGFuZWw=", "c2VnbWVudA==", "YW1wbGl0dWRl",
    "YnJhbmNoLmlv", "YWRqdXN0", "YXBwc2ZseWVy", "a29jaGF2YQ==",
    "cG9wYWRz", "cG9wY2FzaA==", "dGFib29sYQ==", "b3V0YnJhaW4=", nullptr
};

// URL parser
struct URLParts {
    std::string host, path;
    int port;
    bool ssl;
};

URLParts parseURL(const std::string& url) {
    URLParts u; u.ssl = false; u.port = 80;
    size_t p = 0;
    if (url.find("https://") == 0) { u.ssl = true; u.port = 443; p = 8; }
    else if (url.find("http://") == 0) { p = 7; }
    
    size_t ps = url.find('/', p);
    std::string hp = (ps != std::string::npos) ? url.substr(p, ps - p) : url.substr(p);
    
    size_t cp = hp.find(':');
    if (cp != std::string::npos) {
        u.host = hp.substr(0, cp);
        u.port = std::stoi(hp.substr(cp + 1));
    } else u.host = hp;
    
    u.path = (ps != std::string::npos) ? url.substr(ps) : "/";
    return u;
}

// HTTP request
struct HTTPRes {
    int code = 0;
    std::string body;
};

HTTPRes httpGet(const std::string& url, int timeout) {
    HTTPRes res;
    URLParts u = parseURL(url);
    
    #ifdef _WIN32
    WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
    #endif
    
    struct addrinfo hints{}, *addr = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(u.host.c_str(), std::to_string(u.port).c_str(), &hints, &addr) != 0) {
        return res;
    }
    
    SockT sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (sock == BADSOCK) { freeaddrinfo(addr); return res; }
    
    #ifdef _WIN32
    DWORD tv = timeout;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));
    #else
    struct timeval tv; tv.tv_sec = timeout/1000; tv.tv_usec = (timeout%1000)*1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    #endif
    
    if (connect(sock, addr->ai_addr, addr->ai_addrlen) < 0) {
        CLOSESOCK(sock); freeaddrinfo(addr); return res;
    }
    freeaddrinfo(addr);
    
    #if USE_SSL
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    if (u.ssl) {
        SSL_library_init();
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { CLOSESOCK(sock); return res; }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, u.host.c_str());
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl); SSL_CTX_free(ctx); CLOSESOCK(sock); return res;
        }
    }
    #else
    if (u.ssl) { CLOSESOCK(sock); return res; }
    #endif
    
    std::ostringstream req;
    req << "GET " << u.path << " HTTP/1.1\r\n";
    req << "Host: " << u.host << "\r\n";
    req << "Connection: close\r\n";
    req << "User-Agent: okhttp/4.9.3\r\n\r\n";
    
    std::string r = req.str();
    
    #if USE_SSL
    if (ssl) SSL_write(ssl, r.c_str(), r.size());
    else
    #endif
    send(sock, r.c_str(), r.size(), 0);
    
    std::string data;
    char buf[4096];
    int n;
    
    #if USE_SSL
    while ((n = ssl ? SSL_read(ssl, buf, sizeof(buf)-1) : recv(sock, buf, sizeof(buf)-1, 0)) > 0)
    #else
    while ((n = recv(sock, buf, sizeof(buf)-1, 0)) > 0)
    #endif
    {
        buf[n] = 0;
        data += buf;
    }
    
    #if USE_SSL
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
    #endif
    CLOSESOCK(sock);
    #ifdef _WIN32
    WSACleanup();
    #endif
    
    size_t he = data.find("\r\n\r\n");
    if (he != std::string::npos) {
        std::string h = data.substr(0, he);
        res.body = data.substr(he + 4);
        size_t sp = h.find(' ');
        if (sp != std::string::npos) res.code = std::stoi(h.substr(sp + 1));
    }
    
    return res;
}

// JSON helpers
std::string jsonStr(const std::string& j, const std::string& k) {
    std::string s = "\"" + k + "\":\"";
    size_t p = j.find(s);
    if (p == std::string::npos) return "";
    p += s.size();
    size_t e = j.find('"', p);
    return (e != std::string::npos) ? j.substr(p, e - p) : "";
}

int jsonInt(const std::string& j, const std::string& k) {
    std::string s = "\"" + k + "\":";
    size_t p = j.find(s);
    if (p == std::string::npos) return 0;
    p += s.size();
    return std::stoi(j.substr(p));
}

bool jsonBool(const std::string& j, const std::string& k) {
    std::string s = "\"" + k + "\":";
    size_t p = j.find(s);
    if (p == std::string::npos) return false;
    return j.substr(p + s.size(), 4) == "true";
}

// Implementation
class ConfigMgr::Impl {
public:
    std::string endpoint;
    bool active = false;
    int timeout = 10000;
    std::string error;
    
    std::unordered_set<std::string> filters;
    std::vector<std::string> patterns;
    mutable std::shared_mutex mtx;
    
    Impl(const std::string& url) : endpoint(url) {
        if (!endpoint.empty() && endpoint.back() == '/') endpoint.pop_back();
        loadPatterns();
    }
    
    void loadPatterns() {
        for (int i = 0; ENC_DATA[i]; i++) {
            std::string dec = b64dec(ENC_DATA[i]);
            if (!dec.empty()) {
                patterns.push_back(dec);
                filters.insert(dec);
            }
        }
    }
    
    bool matchPattern(const std::string& s) const {
        std::string lower = s;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        for (const auto& p : patterns) {
            if (lower.find(p) != std::string::npos) return true;
        }
        return false;
    }
    
    bool checkFilters(const std::string& s) const {
        std::string n = normalize(s);
        std::shared_lock lock(mtx);
        if (filters.count(n)) return true;
        if (matchPattern(n)) return true;
        
        size_t pos = 0;
        while ((pos = n.find('.', pos)) != std::string::npos) {
            std::string parent = n.substr(pos + 1);
            if (filters.count(parent)) return true;
            pos++;
        }
        return false;
    }
};

// Public methods
ConfigMgr::ConfigMgr(const std::string& endpoint)
    : m(std::make_unique<Impl>(endpoint)) {}

ConfigMgr::~ConfigMgr() = default;

bool ConfigMgr::init() {
    HTTPRes res = httpGet(m->endpoint + "/c", m->timeout);
    if (res.code >= 200 && res.code < 300 && jsonBool(res.body, "ok")) {
        m->active = true;
        return true;
    }
    m->error = "Init failed";
    return false;
}

bool ConfigMgr::check(const std::string& key) {
    if (m->checkFilters(key)) return true;
    
    HTTPRes res = httpGet(m->endpoint + "/k?d=" + key, m->timeout);
    if (res.code >= 200 && res.code < 300) {
        return jsonInt(res.body, "r") == 1;
    }
    return m->checkFilters(key);
}

DataResult ConfigMgr::query(const std::string& key) {
    DataResult r;
    r.key = key;
    
    if (m->checkFilters(key)) {
        r.valid = true;
        r.status = 1;
        r.value = "0.0.0.0";
        return r;
    }
    
    HTTPRes res = httpGet(m->endpoint + "/q?d=" + key, m->timeout);
    if (res.code >= 200 && res.code < 300) {
        r.valid = jsonBool(res.body, "ok");
        r.status = jsonInt(res.body, "r");
        r.value = jsonStr(res.body, "ip");
    }
    return r;
}

std::map<std::string, DataResult> ConfigMgr::queryBatch(const std::vector<std::string>& keys) {
    std::map<std::string, DataResult> results;
    for (const auto& k : keys) {
        results[k] = query(k);
    }
    return results;
}

bool ConfigMgr::checkLocal(const std::string& key) const {
    return m->checkFilters(key);
}

void ConfigMgr::addFilter(const std::string& key) {
    std::lock_guard lock(m->mtx);
    m->filters.insert(normalize(key));
}

void ConfigMgr::removeFilter(const std::string& key) {
    std::lock_guard lock(m->mtx);
    m->filters.erase(normalize(key));
}

void ConfigMgr::queryAsync(const std::string& key, ResultCallback cb) {
    std::thread([this, key, cb]() { cb(query(key)); }).detach();
}

std::future<DataResult> ConfigMgr::queryFuture(const std::string& key) {
    return std::async(std::launch::async, [this, key]() { return query(key); });
}

void ConfigMgr::setTimeout(int ms) { m->timeout = ms; }
bool ConfigMgr::isActive() const { return m->active; }
std::string ConfigMgr::getError() const { return m->error; }

// Helpers
std::string normalize(const std::string& s) {
    std::string r = s;
    if (r.find("http://") == 0) r = r.substr(7);
    if (r.find("https://") == 0) r = r.substr(8);
    size_t p = r.find('/');
    if (p != std::string::npos) r = r.substr(0, p);
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
}

bool isFiltered(const std::string& s) {
    std::string n = normalize(s);
    for (int i = 0; ENC_DATA[i]; i++) {
        std::string dec = b64dec(ENC_DATA[i]);
        if (n.find(dec) != std::string::npos) return true;
    }
    return false;
}

} // namespace GameConfig

// C API
static std::string g_result;

extern "C" {

void* gcfg_create(const char* url) {
    if (!url) return nullptr;
    return new GameConfig::ConfigMgr(url);
}

void gcfg_destroy(void* h) {
    delete static_cast<GameConfig::ConfigMgr*>(h);
}

int gcfg_init(void* h) {
    if (!h) return 0;
    return static_cast<GameConfig::ConfigMgr*>(h)->init() ? 1 : 0;
}

int gcfg_check(void* h, const char* key) {
    if (!h || !key) return 0;
    return static_cast<GameConfig::ConfigMgr*>(h)->check(key) ? 1 : 0;
}

const char* gcfg_query(void* h, const char* key) {
    if (!h || !key) return "0.0.0.0";
    auto r = static_cast<GameConfig::ConfigMgr*>(h)->query(key);
    g_result = (r.status == 1) ? "0.0.0.0" : r.value;
    return g_result.c_str();
}

int gcfg_check_local(void* h, const char* key) {
    if (!h || !key) return 0;
    return static_cast<GameConfig::ConfigMgr*>(h)->checkLocal(key) ? 1 : 0;
}

void gcfg_add(void* h, const char* key) {
    if (h && key) static_cast<GameConfig::ConfigMgr*>(h)->addFilter(key);
}

void gcfg_timeout(void* h, int ms) {
    if (h) static_cast<GameConfig::ConfigMgr*>(h)->setTimeout(ms);
}

}
