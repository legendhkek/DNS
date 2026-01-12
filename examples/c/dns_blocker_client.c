/**
 * DNS Blocker API Client Implementation for C/C++
 * 
 * Dependencies: libcurl, cJSON (included inline for simplicity)
 * Compile: gcc -o myapp myapp.c dns_blocker_client.c -lcurl
 */

#include "dns_blocker_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

// Simple JSON parser (minimal implementation)
typedef struct {
    char* data;
    size_t size;
} response_buffer_t;

// CURL write callback
static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    response_buffer_t* mem = (response_buffer_t*)userp;
    
    char* ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) {
        return 0;
    }
    
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    
    return realsize;
}

// Simple JSON value extractor (for our specific use case)
static bool json_get_bool(const char* json, const char* key, bool default_val) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    
    const char* pos = strstr(json, search);
    if (!pos) return default_val;
    
    pos += strlen(search);
    while (*pos == ' ' || *pos == '\t') pos++;
    
    if (strncmp(pos, "true", 4) == 0) return true;
    if (strncmp(pos, "false", 5) == 0) return false;
    
    return default_val;
}

static bool json_get_string(const char* json, const char* key, char* out, size_t out_size) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    
    const char* pos = strstr(json, search);
    if (!pos) return false;
    
    pos += strlen(search);
    while (*pos == ' ' || *pos == '\t') pos++;
    
    if (*pos == '"') {
        pos++;
        const char* end = strchr(pos, '"');
        if (end) {
            size_t len = end - pos;
            if (len >= out_size) len = out_size - 1;
            strncpy(out, pos, len);
            out[len] = 0;
            return true;
        }
    } else if (*pos == 'n' && strncmp(pos, "null", 4) == 0) {
        out[0] = 0;
        return true;
    }
    
    return false;
}

static int json_get_int(const char* json, const char* key, int default_val) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    
    const char* pos = strstr(json, search);
    if (!pos) return default_val;
    
    pos += strlen(search);
    while (*pos == ' ' || *pos == '\t') pos++;
    
    if (*pos >= '0' && *pos <= '9') {
        return atoi(pos);
    }
    
    return default_val;
}

// Make HTTP request
static char* make_request(dns_client_t* client, const char* endpoint, const char* method, const char* body) {
    CURL* curl;
    CURLcode res;
    response_buffer_t response = {0};
    
    response.data = malloc(1);
    response.data[0] = 0;
    response.size = 0;
    
    curl = curl_easy_init();
    if (!curl) {
        free(response.data);
        snprintf(client->last_error, DNS_MAX_ERROR_LEN, "Failed to initialize CURL");
        return NULL;
    }
    
    // Build URL
    char url[DNS_MAX_URL_LEN * 2];
    snprintf(url, sizeof(url), "%s%s", client->server_url, endpoint);
    
    // Set URL
    curl_easy_setopt(curl, CURLOPT_URL, url);
    
    // Set timeout
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, client->timeout_ms);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, client->timeout_ms / 2);
    
    // Set headers
    struct curl_slist* headers = NULL;
    char auth_header[DNS_MAX_KEY_LEN + 16];
    snprintf(auth_header, sizeof(auth_header), "X-API-Key: %s", client->api_key);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    // Set method
    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (body) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        }
    }
    
    // Set write callback
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);
    
    // SSL options (for production, properly configure certificates)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    // Perform request
    res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        snprintf(client->last_error, DNS_MAX_ERROR_LEN, "CURL error: %s", curl_easy_strerror(res));
        free(response.data);
        return NULL;
    }
    
    return response.data;
}

// Initialize client
dns_client_t* dns_client_init(const char* server_url, const char* api_key) {
    if (!server_url || !api_key) {
        return NULL;
    }
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    dns_client_t* client = (dns_client_t*)malloc(sizeof(dns_client_t));
    if (!client) {
        return NULL;
    }
    
    memset(client, 0, sizeof(dns_client_t));
    
    // Copy server URL (remove trailing slash if present)
    strncpy(client->server_url, server_url, DNS_MAX_URL_LEN - 1);
    size_t len = strlen(client->server_url);
    if (len > 0 && client->server_url[len - 1] == '/') {
        client->server_url[len - 1] = 0;
    }
    
    strncpy(client->api_key, api_key, DNS_MAX_KEY_LEN - 1);
    client->timeout_ms = 10000; // 10 seconds default
    client->connected = false;
    
    return client;
}

// Free client
void dns_client_free(dns_client_t* client) {
    if (client) {
        free(client);
    }
    curl_global_cleanup();
}

// Connect to API
bool dns_client_connect(dns_client_t* client) {
    if (!client) {
        return false;
    }
    
    char* response = make_request(client, "/connect", "GET", NULL);
    if (!response) {
        return false;
    }
    
    bool success = json_get_bool(response, "success", false);
    if (success) {
        client->connected = true;
    } else {
        json_get_string(response, "error", client->last_error, DNS_MAX_ERROR_LEN);
    }
    
    free(response);
    return success;
}

// Resolve domain
bool dns_client_resolve(dns_client_t* client, const char* domain, dns_result_t* result) {
    if (!client || !domain || !result) {
        return false;
    }
    
    memset(result, 0, sizeof(dns_result_t));
    strncpy(result->domain, domain, DNS_MAX_DOMAIN_LEN - 1);
    
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/resolve?domain=%s", domain);
    
    char* response = make_request(client, endpoint, "GET", NULL);
    if (!response) {
        return false;
    }
    
    result->success = json_get_bool(response, "success", false);
    result->blocked = json_get_bool(response, "blocked", false);
    result->ttl = json_get_int(response, "ttl", 300);
    json_get_string(response, "ip", result->ip, DNS_MAX_IP_LEN);
    json_get_string(response, "ipv6", result->ipv6, DNS_MAX_IP_LEN);
    
    free(response);
    return result->success;
}

// Check if domain is blocked
bool dns_client_is_blocked(dns_client_t* client, const char* domain) {
    if (!client || !domain) {
        return false;
    }
    
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/check?domain=%s", domain);
    
    char* response = make_request(client, endpoint, "GET", NULL);
    if (!response) {
        return false;
    }
    
    bool blocked = json_get_bool(response, "blocked", false);
    free(response);
    
    return blocked;
}

// Get API status
bool dns_client_status(dns_client_t* client, dns_status_t* status) {
    if (!client || !status) {
        return false;
    }
    
    memset(status, 0, sizeof(dns_status_t));
    
    char* response = make_request(client, "/status", "GET", NULL);
    if (!response) {
        return false;
    }
    
    bool success = json_get_bool(response, "success", false);
    if (success) {
        char status_str[32];
        json_get_string(response, "status", status_str, sizeof(status_str));
        status->online = (strcmp(status_str, "online") == 0);
        json_get_string(response, "version", status->version, sizeof(status->version));
        status->blocked_domains_count = json_get_int(response, "blocked_domains", 0);
        json_get_string(response, "server_time", status->server_time, sizeof(status->server_time));
    }
    
    free(response);
    return success;
}

// Set timeout
void dns_client_set_timeout(dns_client_t* client, int timeout_ms) {
    if (client && timeout_ms > 0) {
        client->timeout_ms = timeout_ms;
    }
}

// Get last error
const char* dns_client_get_error(dns_client_t* client) {
    if (client) {
        return client->last_error;
    }
    return "Invalid client";
}

// Check if connected
bool dns_client_is_connected(dns_client_t* client) {
    return client && client->connected;
}
