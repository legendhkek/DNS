/**
 * Game Config - Single header, encrypted communication
 * 
 * Usage:
 *   #include "GameConfig.h"
 *   
 *   gcfg_init("http://your-server.com/Dns.php");
 *   
 *   if (gcfg_block("doubleclick.net")) {
 *       // block this
 *   }
 */

#ifndef GAME_CONFIG_H
#define GAME_CONFIG_H

#include <string>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define CLOSESOCK closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#define CLOSESOCK close
#endif

namespace {

// ============ GLOBALS ============
std::string g_url = "";
std::string g_key = "";
bool g_init = false;

// Built-in patterns (obfuscated)
const char* g_enc_patterns[] = {
    "ZG91YmxlY2xpY2s=", "Z29vZ2xlc3luZGljYXRpb24=", "Z29vZ2xlYWRzZXJ2aWNlcw==",
    "Z29vZ2xlLWFuYWx5dGljcw==", "Z29vZ2xldGFnbWFuYWdlcg==", "YWRzZXJ2aWNl",
    "cGFnZWFk", "YWRtb2I=", "YWRzZW5zZQ==", "YWRueHM=", "YWR2ZXJ0aXNpbmc=",
    "bW9wdWI=", "dW5pdHlhZHM=", "YXBwbG92aW4=", "dnVuZ2xl", "Y2hhcnRib29zdA==",
    "aXJvbnNyYw==", "aW5tb2Jp", "dGFwam95", "ZnliZXI=", "YW4uZmFjZWJvb2s=",
    "cGl4ZWwuZmFjZWJvb2s=", "YW5hbHl0aWNz", "dHJhY2tlcg==", "dHJhY2tpbmc=",
    "dGVsZW1ldHJ5", "bWl4cGFuZWw=", "c2VnbWVudA==", "YW1wbGl0dWRl",
    "YnJhbmNoLmlv", "YWRqdXN0", "YXBwc2ZseWVy", "a29jaGF2YQ==",
    "cG9wYWRz", "cG9wY2FzaA==", "dGFib29sYQ==", "b3V0YnJhaW4=",
    "Y3Jhc2hseXRpY3M=", "Zmx1cnJ5", nullptr
};

std::vector<std::string> g_patterns;

// ============ BASE64 ============
const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64enc(const std::string& s) {
    std::string r;
    int v = 0, b = -6;
    for (unsigned char c : s) {
        v = (v << 8) + c; b += 8;
        while (b >= 0) { r += B64[(v >> b) & 0x3F]; b -= 6; }
    }
    if (b > -6) r += B64[((v << 8) >> (b + 8)) & 0x3F];
    while (r.size() % 4) r += '=';
    return r;
}

std::string b64dec(const std::string& s) {
    std::string r;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(int)B64[i]] = i;
    int v = 0, b = -8;
    for (char c : s) {
        if (T[(int)(unsigned char)c] == -1) break;
        v = (v << 6) + T[(int)(unsigned char)c];
        b += 6;
        if (b >= 0) { r += char((v >> b) & 0xFF); b -= 8; }
    }
    return r;
}

// ============ XOR CIPHER ============
std::string xorCrypt(const std::string& data, const std::string& key) {
    std::string r;
    for (size_t i = 0; i < data.size(); i++) {
        r += data[i] ^ key[i % key.size()];
    }
    return r;
}

// ============ ENCRYPT/DECRYPT ============
std::string encryptData(const std::string& json, const std::string& key) {
    std::string x = xorCrypt(json, key);
    std::string b = b64enc(x);
    // Add random padding
    char pad[8];
    for (int i = 0; i < 8; i++) pad[i] = 'a' + (rand() % 26);
    std::string p(pad, 8);
    return p + "." + b + "." + b.substr(0, 8);
}

std::string decryptData(const std::string& data, const std::string& key) {
    // Find the base64 part between dots
    size_t d1 = data.find('.');
    size_t d2 = data.rfind('.');
    if (d1 == std::string::npos || d1 == d2) return "";
    
    std::string b64 = data.substr(d1 + 1, d2 - d1 - 1);
    std::string decoded = b64dec(b64);
    return xorCrypt(decoded, key);
}

// ============ JSON HELPERS ============
std::string jsonGetStr(const std::string& j, const std::string& k) {
    std::string search = "\"" + k + "\":\"";
    size_t p = j.find(search);
    if (p == std::string::npos) {
        search = "\"" + k + "\": \"";
        p = j.find(search);
    }
    if (p == std::string::npos) return "";
    p += search.size();
    size_t e = j.find("\"", p);
    return (e != std::string::npos) ? j.substr(p, e - p) : "";
}

int jsonGetInt(const std::string& j, const std::string& k) {
    std::string search = "\"" + k + "\":";
    size_t p = j.find(search);
    if (p == std::string::npos) {
        search = "\"" + k + "\": ";
        p = j.find(search);
    }
    if (p == std::string::npos) return 0;
    p += search.size();
    while (p < j.size() && (j[p] == ' ' || j[p] == '\t')) p++;
    return atoi(j.c_str() + p);
}

std::string normalize(const std::string& s) {
    std::string r = s;
    if (r.find("http://") == 0) r = r.substr(7);
    if (r.find("https://") == 0) r = r.substr(8);
    size_t p = r.find('/');
    if (p != std::string::npos) r = r.substr(0, p);
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
}

// ============ HTTP ============
std::string httpReq(const std::string& url, const std::string& body = "") {
    std::string result;
    
    bool ssl = (url.find("https://") == 0);
    size_t start = ssl ? 8 : (url.find("http://") == 0 ? 7 : 0);
    size_t ps = url.find('/', start);
    std::string hp = (ps != std::string::npos) ? url.substr(start, ps - start) : url.substr(start);
    std::string path = (ps != std::string::npos) ? url.substr(ps) : "/";
    
    std::string host = hp;
    int port = ssl ? 443 : 80;
    size_t cp = hp.find(':');
    if (cp != std::string::npos) {
        host = hp.substr(0, cp);
        port = atoi(hp.c_str() + cp + 1);
    }
    
    if (ssl) return result; // Skip SSL for simplicity
    
    #ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    #endif
    
    struct addrinfo hints = {}, *addr = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    char portStr[16];
    snprintf(portStr, sizeof(portStr), "%d", port);
    
    if (getaddrinfo(host.c_str(), portStr, &hints, &addr) != 0) return result;
    
    int sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (sock < 0) { freeaddrinfo(addr); return result; }
    
    #ifdef _WIN32
    DWORD tv = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    #else
    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    #endif
    
    if (connect(sock, addr->ai_addr, addr->ai_addrlen) < 0) {
        CLOSESOCK(sock); freeaddrinfo(addr); return result;
    }
    freeaddrinfo(addr);
    
    std::string req;
    if (body.empty()) {
        req = "GET " + path + " HTTP/1.1\r\n";
    } else {
        req = "POST " + path + " HTTP/1.1\r\n";
        req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        req += "Content-Type: application/octet-stream\r\n";
    }
    req += "Host: " + host + "\r\n";
    req += "User-Agent: UnityPlayer/2021.3.15f1\r\n";
    req += "X-Unity-Version: 2021.3.15f1\r\n";
    req += "Connection: close\r\n\r\n";
    req += body;
    
    send(sock, req.c_str(), req.size(), 0);
    
    std::string resp;
    char buf[4096];
    int n;
    while ((n = recv(sock, buf, sizeof(buf)-1, 0)) > 0) {
        buf[n] = 0;
        resp += buf;
    }
    
    CLOSESOCK(sock);
    #ifdef _WIN32
    WSACleanup();
    #endif
    
    size_t bodyStart = resp.find("\r\n\r\n");
    if (bodyStart != std::string::npos) {
        result = resp.substr(bodyStart + 4);
    }
    
    return result;
}

// ============ INIT PATTERNS ============
void initPatterns() {
    if (!g_patterns.empty()) return;
    for (int i = 0; g_enc_patterns[i]; i++) {
        std::string dec = b64dec(g_enc_patterns[i]);
        if (!dec.empty()) g_patterns.push_back(dec);
    }
}

// ============ LOCAL CHECK ============
bool checkLocal(const std::string& domain) {
    initPatterns();
    std::string d = normalize(domain);
    for (const auto& p : g_patterns) {
        if (d.find(p) != std::string::npos) return true;
    }
    return false;
}

// ============ EXTRACT CONFIG FROM FAKE GAME DATA ============
std::string extractConfig(const std::string& response) {
    // Find "config" field in the fake game data
    std::string search = "\"config\":\"";
    size_t p = response.find(search);
    if (p == std::string::npos) {
        search = "\"config\": \"";
        p = response.find(search);
    }
    if (p == std::string::npos) return response; // Not wrapped
    
    p += search.size();
    size_t e = response.find("\"", p);
    if (e == std::string::npos) return "";
    
    return response.substr(p, e - p);
}

} // anonymous namespace

// ============ PUBLIC API ============

// Initialize with server URL
inline bool gcfg_init(const std::string& url) {
    g_url = url;
    if (!g_url.empty() && g_url.back() == '/') g_url.pop_back();
    
    initPatterns();
    srand(time(nullptr));
    
    // Get encryption key from server
    std::string resp = httpReq(g_url + "/?a=i");
    if (resp.empty()) {
        g_init = true; // Use local only
        return true;
    }
    
    // Extract encrypted config
    std::string config = extractConfig(resp);
    
    // Try to find key in response
    std::string k = jsonGetStr(resp, "k");
    if (k.empty()) {
        // Try decrypting with time-based key
        time_t now = time(nullptr);
        struct tm* t = gmtime(&now);
        char timeBuf[32];
        strftime(timeBuf, sizeof(timeBuf), "%Y%m%d%H", t);
        g_key = b64enc(std::string(timeBuf) + "gx");
    } else {
        g_key = k;
    }
    
    // Try to decrypt config
    if (!config.empty() && config.find('.') != std::string::npos) {
        std::string dec = decryptData(config, g_key);
        if (!dec.empty() && jsonGetInt(dec, "s") == 1) {
            g_key = jsonGetStr(dec, "k");
            if (g_key.empty()) g_key = k;
        }
    }
    
    g_init = true;
    return true;
}

// Check if should block (local + server)
inline bool gcfg_block(const std::string& domain) {
    if (!g_init) gcfg_init(g_url);
    
    // Fast local check first
    if (checkLocal(domain)) return true;
    
    // Server check if URL set
    if (!g_url.empty() && !g_key.empty()) {
        std::string d = normalize(domain);
        std::string body = encryptData("{\"a\":\"k\",\"d\":\"" + d + "\"}", g_key);
        std::string resp = httpReq(g_url, body);
        
        if (!resp.empty()) {
            std::string config = extractConfig(resp);
            std::string dec = decryptData(config, g_key);
            if (!dec.empty()) {
                if (jsonGetInt(dec, "f") == 1) return true;
            }
        }
    }
    
    return false;
}

// Local check only (very fast, no network)
inline bool gcfg_block_local(const std::string& domain) {
    initPatterns();
    return checkLocal(domain);
}

// Query with full response
inline std::string gcfg_query(const std::string& domain) {
    if (!g_init) gcfg_init(g_url);
    
    if (checkLocal(domain)) return "0.0.0.0";
    
    if (!g_url.empty() && !g_key.empty()) {
        std::string d = normalize(domain);
        std::string body = encryptData("{\"a\":\"q\",\"d\":\"" + d + "\"}", g_key);
        std::string resp = httpReq(g_url, body);
        
        if (!resp.empty()) {
            std::string config = extractConfig(resp);
            std::string dec = decryptData(config, g_key);
            if (!dec.empty()) {
                if (jsonGetInt(dec, "f") == 1) return "0.0.0.0";
                std::string ip = jsonGetStr(dec, "v");
                if (!ip.empty()) return ip;
            }
        }
    }
    
    return "";
}

// Add custom pattern to local filter
inline void gcfg_add(const std::string& pattern) {
    initPatterns();
    std::string p = normalize(pattern);
    if (!p.empty()) g_patterns.push_back(p);
}

// Set URL (alternative to init)
inline void gcfg_set_url(const std::string& url) {
    g_url = url;
    if (!g_url.empty() && g_url.back() == '/') g_url.pop_back();
}

#endif // GAME_CONFIG_H
