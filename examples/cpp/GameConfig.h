/**
 * Single header - just include and use
 * 
 * Usage:
 *   #include "GameConfig.h"
 *   
 *   // Set your server URL once
 *   gcfg_set_url("https://your-server.com/Dns.php");
 *   
 *   // Check if should block (returns true if ad/tracker)
 *   if (gcfg_block("doubleclick.net")) {
 *       // block this request
 *   }
 */

#ifndef GAME_CONFIG_H
#define GAME_CONFIG_H

#include <string>
#include <cstring>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif

// ============ CONFIG ============
static std::string g_server_url = "";

// Blocked patterns (base64 decoded)
static const char* g_patterns[] = {
    "doubleclick", "googlesyndication", "googleadservices", "google-analytics",
    "googletagmanager", "adservice", "pagead", "admob", "adsense", "adnxs",
    "advertising", "mopub", "unityads", "applovin", "vungle", "chartboost",
    "ironsrc", "inmobi", "tapjoy", "fyber", "an.facebook", "pixel.facebook",
    "analytics", "tracker", "tracking", "telemetry", "mixpanel", "segment",
    "amplitude", "branch.io", "adjust", "appsflyer", "kochava", "popads",
    "popcash", "taboola", "outbrain", "crashlytics", "flurry", nullptr
};

// ============ FUNCTIONS ============

// Set server URL
inline void gcfg_set_url(const std::string& url) {
    g_server_url = url;
    if (!g_server_url.empty() && g_server_url.back() == '/') {
        g_server_url.pop_back();
    }
}

// Normalize domain
inline std::string gcfg_normalize(const std::string& s) {
    std::string r = s;
    if (r.find("http://") == 0) r = r.substr(7);
    if (r.find("https://") == 0) r = r.substr(8);
    size_t p = r.find('/');
    if (p != std::string::npos) r = r.substr(0, p);
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
}

// Local check (fast, no network) - checks against built-in patterns
inline bool gcfg_block_local(const std::string& domain) {
    std::string d = gcfg_normalize(domain);
    for (int i = 0; g_patterns[i]; i++) {
        if (d.find(g_patterns[i]) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// HTTP request helper
inline std::string gcfg_http_get(const std::string& url) {
    std::string result;
    
    // Parse URL
    bool use_ssl = (url.find("https://") == 0);
    size_t start = use_ssl ? 8 : (url.find("http://") == 0 ? 7 : 0);
    size_t path_start = url.find('/', start);
    std::string host_port = (path_start != std::string::npos) ? url.substr(start, path_start - start) : url.substr(start);
    std::string path = (path_start != std::string::npos) ? url.substr(path_start) : "/";
    
    std::string host = host_port;
    int port = use_ssl ? 443 : 80;
    size_t colon = host_port.find(':');
    if (colon != std::string::npos) {
        host = host_port.substr(0, colon);
        port = std::stoi(host_port.substr(colon + 1));
    }
    
    // Skip SSL for simplicity (use HTTP or handle SSL in your app)
    if (use_ssl) return result;
    
    #ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    #endif
    
    struct addrinfo hints = {}, *addr = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &addr) != 0) {
        return result;
    }
    
    int sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (sock < 0) { freeaddrinfo(addr); return result; }
    
    // Timeout
    #ifdef _WIN32
    DWORD tv = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    #else
    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    #endif
    
    if (connect(sock, addr->ai_addr, addr->ai_addrlen) < 0) {
        #ifdef _WIN32
        closesocket(sock);
        #else
        close(sock);
        #endif
        freeaddrinfo(addr);
        return result;
    }
    freeaddrinfo(addr);
    
    // Send request
    std::string req = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    send(sock, req.c_str(), req.size(), 0);
    
    // Receive
    char buf[4096];
    int n;
    std::string resp;
    while ((n = recv(sock, buf, sizeof(buf)-1, 0)) > 0) {
        buf[n] = 0;
        resp += buf;
    }
    
    #ifdef _WIN32
    closesocket(sock);
    WSACleanup();
    #else
    close(sock);
    #endif
    
    // Extract body
    size_t body_start = resp.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        result = resp.substr(body_start + 4);
    }
    
    return result;
}

// Check with server (if URL set) or local
inline bool gcfg_block(const std::string& domain) {
    // Always check local first (fast)
    if (gcfg_block_local(domain)) {
        return true;
    }
    
    // If server URL set, check remotely
    if (!g_server_url.empty()) {
        std::string url = g_server_url + "/k?d=" + gcfg_normalize(domain);
        std::string resp = gcfg_http_get(url);
        if (resp.find("\"r\":1") != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

// Query and get IP (returns "0.0.0.0" if blocked)
inline std::string gcfg_query(const std::string& domain) {
    if (gcfg_block_local(domain)) {
        return "0.0.0.0";
    }
    
    if (!g_server_url.empty()) {
        std::string url = g_server_url + "/q?d=" + gcfg_normalize(domain);
        std::string resp = gcfg_http_get(url);
        
        // Check if blocked
        if (resp.find("\"r\":1") != std::string::npos) {
            return "0.0.0.0";
        }
        
        // Extract IP
        size_t ip_pos = resp.find("\"ip\":\"");
        if (ip_pos != std::string::npos) {
            ip_pos += 6;
            size_t ip_end = resp.find("\"", ip_pos);
            if (ip_end != std::string::npos) {
                return resp.substr(ip_pos, ip_end - ip_pos);
            }
        }
    }
    
    return "";
}

#endif // GAME_CONFIG_H
