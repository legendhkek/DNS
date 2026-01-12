/**
 * DNS Blocker API Client Implementation for C++
 */

#include "DnsBlockerClient.hpp"
#include <curl/curl.h>
#include <sstream>
#include <regex>
#include <stdexcept>

namespace DnsBlocker {

// Simple JSON helpers (for minimal dependencies)
namespace json {
    std::string getValue(const std::string& json, const std::string& key) {
        std::string search = "\"" + key + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";
        
        pos += search.length();
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
        
        if (json[pos] == '"') {
            size_t start = pos + 1;
            size_t end = json.find('"', start);
            if (end != std::string::npos) {
                return json.substr(start, end - start);
            }
        } else if (json[pos] == 'n' && json.substr(pos, 4) == "null") {
            return "";
        } else {
            size_t end = json.find_first_of(",}]", pos);
            if (end != std::string::npos) {
                return json.substr(pos, end - pos);
            }
        }
        return "";
    }
    
    bool getBool(const std::string& json, const std::string& key, bool defaultVal = false) {
        std::string val = getValue(json, key);
        if (val == "true") return true;
        if (val == "false") return false;
        return defaultVal;
    }
    
    int getInt(const std::string& json, const std::string& key, int defaultVal = 0) {
        std::string val = getValue(json, key);
        if (val.empty()) return defaultVal;
        try {
            return std::stoi(val);
        } catch (...) {
            return defaultVal;
        }
    }
    
    std::string getString(const std::string& json, const std::string& key) {
        return getValue(json, key);
    }
    
    std::vector<std::string> getStringArray(const std::string& json, const std::string& key) {
        std::vector<std::string> result;
        std::string search = "\"" + key + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return result;
        
        pos = json.find('[', pos);
        if (pos == std::string::npos) return result;
        
        size_t end = json.find(']', pos);
        if (end == std::string::npos) return result;
        
        std::string arr = json.substr(pos + 1, end - pos - 1);
        
        std::regex re("\"([^\"]+)\"");
        std::smatch match;
        std::string::const_iterator searchStart(arr.cbegin());
        while (std::regex_search(searchStart, arr.cend(), match, re)) {
            result.push_back(match[1]);
            searchStart = match.suffix().first;
        }
        
        return result;
    }
    
    std::string buildObject(const std::map<std::string, std::string>& obj) {
        std::ostringstream oss;
        oss << "{";
        bool first = true;
        for (const auto& [key, value] : obj) {
            if (!first) oss << ",";
            oss << "\"" << key << "\":" << value;
            first = false;
        }
        oss << "}";
        return oss.str();
    }
    
    std::string buildArray(const std::vector<std::string>& arr) {
        std::ostringstream oss;
        oss << "[";
        bool first = true;
        for (const auto& item : arr) {
            if (!first) oss << ",";
            oss << "\"" << item << "\"";
            first = false;
        }
        oss << "]";
        return oss.str();
    }
}

// CURL response buffer
struct ResponseBuffer {
    std::string data;
    
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        size_t realsize = size * nmemb;
        ResponseBuffer* mem = static_cast<ResponseBuffer*>(userp);
        mem->data.append(static_cast<char*>(contents), realsize);
        return realsize;
    }
};

// Implementation class
class Client::Impl {
public:
    std::string serverUrl;
    std::string apiKey;
    bool connected = false;
    int timeoutMs = 10000;
    std::string lastError;
    
    Impl(const std::string& url, const std::string& key) 
        : serverUrl(url), apiKey(key) {
        // Remove trailing slash
        if (!serverUrl.empty() && serverUrl.back() == '/') {
            serverUrl.pop_back();
        }
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }
    
    ~Impl() {
        curl_global_cleanup();
    }
    
    std::string makeRequest(const std::string& endpoint, 
                           const std::string& method = "GET",
                           const std::string& body = "") {
        CURL* curl = curl_easy_init();
        if (!curl) {
            lastError = "Failed to initialize CURL";
            return "";
        }
        
        ResponseBuffer response;
        std::string url = serverUrl + endpoint;
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeoutMs);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeoutMs / 2);
        
        // Headers
        struct curl_slist* headers = nullptr;
        std::string authHeader = "X-API-Key: " + apiKey;
        headers = curl_slist_append(headers, authHeader.c_str());
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Accept: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        // Method
        if (method == "POST") {
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            if (!body.empty()) {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
            }
        }
        
        // Response
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ResponseBuffer::writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        
        // SSL
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        
        CURLcode res = curl_easy_perform(curl);
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        
        if (res != CURLE_OK) {
            lastError = std::string("CURL error: ") + curl_easy_strerror(res);
            return "";
        }
        
        return response.data;
    }
};

// Client implementation
Client::Client(const std::string& serverUrl, const std::string& apiKey)
    : pImpl(std::make_unique<Impl>(serverUrl, apiKey)) {}

Client::~Client() = default;

Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&&) noexcept = default;

ConnectionInfo Client::connect() {
    ConnectionInfo info;
    
    std::string response = pImpl->makeRequest("/connect");
    if (response.empty()) {
        info.error = pImpl->lastError;
        return info;
    }
    
    info.success = json::getBool(response, "success");
    if (info.success) {
        pImpl->connected = true;
        info.clientIp = json::getString(response, "client_ip");
        info.serverTime = json::getInt(response, "server_time");
        info.blockedDomainsCount = json::getInt(response, "blocked_domains_count");
        info.message = json::getString(response, "message");
    } else {
        info.error = json::getString(response, "error");
        pImpl->lastError = info.error;
    }
    
    return info;
}

ResolveResult Client::resolve(const std::string& domain) {
    ResolveResult result;
    result.domain = domain;
    
    std::string response = pImpl->makeRequest("/resolve?domain=" + domain);
    if (response.empty()) {
        return result;
    }
    
    result.success = json::getBool(response, "success");
    result.blocked = json::getBool(response, "blocked");
    result.ip = json::getString(response, "ip");
    result.ipv6 = json::getString(response, "ipv6");
    result.ttl = json::getInt(response, "ttl", 300);
    result.reason = json::getString(response, "reason");
    
    return result;
}

bool Client::isBlocked(const std::string& domain) {
    std::string response = pImpl->makeRequest("/check?domain=" + domain);
    if (response.empty()) return false;
    return json::getBool(response, "blocked");
}

std::map<std::string, ResolveResult> Client::bulkResolve(const std::vector<std::string>& domains) {
    std::map<std::string, ResolveResult> results;
    
    std::string body = "{\"domains\":" + json::buildArray(domains) + "}";
    std::string response = pImpl->makeRequest("/bulk-resolve", "POST", body);
    
    if (response.empty()) return results;
    
    // Parse results (simplified - in production use a proper JSON library)
    for (const auto& domain : domains) {
        ResolveResult result;
        result.domain = domain;
        result.success = true;
        
        // Find domain in response
        size_t pos = response.find("\"" + domain + "\"");
        if (pos != std::string::npos) {
            size_t blockPos = response.find("\"blocked\"", pos);
            if (blockPos != std::string::npos && blockPos < pos + 200) {
                result.blocked = response.find("true", blockPos) < response.find("false", blockPos);
            }
        }
        
        results[domain] = result;
    }
    
    return results;
}

ApiStatus Client::getStatus() {
    ApiStatus status;
    
    std::string response = pImpl->makeRequest("/status");
    if (response.empty()) return status;
    
    std::string statusStr = json::getString(response, "status");
    status.online = (statusStr == "online");
    status.version = json::getString(response, "version");
    status.blockedDomainsCount = json::getInt(response, "blocked_domains");
    status.serverTime = json::getString(response, "server_time");
    
    return status;
}

std::vector<std::string> Client::getBlocklist() {
    std::string response = pImpl->makeRequest("/blocklist");
    if (response.empty()) return {};
    return json::getStringArray(response, "domains");
}

bool Client::addToBlocklist(const std::vector<std::string>& domains) {
    std::string body = "{\"add\":" + json::buildArray(domains) + "}";
    std::string response = pImpl->makeRequest("/blocklist", "POST", body);
    return json::getBool(response, "success");
}

bool Client::removeFromBlocklist(const std::vector<std::string>& domains) {
    std::string body = "{\"remove\":" + json::buildArray(domains) + "}";
    std::string response = pImpl->makeRequest("/blocklist", "POST", body);
    return json::getBool(response, "success");
}

void Client::setTimeout(int timeoutMs) {
    pImpl->timeoutMs = timeoutMs;
}

std::string Client::getLastError() const {
    return pImpl->lastError;
}

bool Client::isConnected() const {
    return pImpl->connected;
}

} // namespace DnsBlocker
