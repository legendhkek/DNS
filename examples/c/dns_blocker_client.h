/**
 * DNS Blocker API Client for C/C++
 * 
 * A lightweight HTTP client for connecting to DNS Blocker API
 * 
 * Dependencies: libcurl
 * Compile: gcc -o myapp myapp.c dns_blocker_client.c -lcurl
 * 
 * Usage:
 *   dns_client_t* client = dns_client_init("https://your-server.com/Dns.php", "your-api-key");
 *   
 *   if (dns_client_connect(client)) {
 *       dns_result_t result;
 *       if (dns_client_resolve(client, "doubleclick.net", &result)) {
 *           if (result.blocked) {
 *               printf("Domain blocked: %s\n", result.domain);
 *           } else {
 *               printf("Resolved: %s -> %s\n", result.domain, result.ip);
 *           }
 *       }
 *   }
 *   
 *   dns_client_free(client);
 */

#ifndef DNS_BLOCKER_CLIENT_H
#define DNS_BLOCKER_CLIENT_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum string lengths
#define DNS_MAX_URL_LEN     512
#define DNS_MAX_KEY_LEN     128
#define DNS_MAX_DOMAIN_LEN  256
#define DNS_MAX_IP_LEN      64
#define DNS_MAX_ERROR_LEN   256

// DNS Client structure
typedef struct {
    char server_url[DNS_MAX_URL_LEN];
    char api_key[DNS_MAX_KEY_LEN];
    bool connected;
    int timeout_ms;
    char last_error[DNS_MAX_ERROR_LEN];
} dns_client_t;

// DNS Resolution result
typedef struct {
    char domain[DNS_MAX_DOMAIN_LEN];
    char ip[DNS_MAX_IP_LEN];
    char ipv6[DNS_MAX_IP_LEN];
    bool blocked;
    bool success;
    int ttl;
} dns_result_t;

// API Status
typedef struct {
    bool online;
    char version[32];
    int blocked_domains_count;
    char server_time[32];
} dns_status_t;

/**
 * Initialize DNS Blocker client
 * @param server_url API server URL (e.g., "https://example.com/Dns.php")
 * @param api_key Your API key
 * @return Pointer to client structure, NULL on failure
 */
dns_client_t* dns_client_init(const char* server_url, const char* api_key);

/**
 * Free DNS client resources
 * @param client Client to free
 */
void dns_client_free(dns_client_t* client);

/**
 * Connect to DNS Blocker API
 * @param client Client instance
 * @return true on success, false on failure
 */
bool dns_client_connect(dns_client_t* client);

/**
 * Resolve a domain with ad blocking
 * @param client Client instance
 * @param domain Domain to resolve
 * @param result Pointer to result structure
 * @return true on success, false on failure
 */
bool dns_client_resolve(dns_client_t* client, const char* domain, dns_result_t* result);

/**
 * Check if a domain is blocked
 * @param client Client instance
 * @param domain Domain to check
 * @return true if blocked, false otherwise
 */
bool dns_client_is_blocked(dns_client_t* client, const char* domain);

/**
 * Get API status
 * @param client Client instance
 * @param status Pointer to status structure
 * @return true on success, false on failure
 */
bool dns_client_status(dns_client_t* client, dns_status_t* status);

/**
 * Set connection timeout
 * @param client Client instance
 * @param timeout_ms Timeout in milliseconds
 */
void dns_client_set_timeout(dns_client_t* client, int timeout_ms);

/**
 * Get last error message
 * @param client Client instance
 * @return Error message string
 */
const char* dns_client_get_error(dns_client_t* client);

/**
 * Check if client is connected
 * @param client Client instance
 * @return true if connected
 */
bool dns_client_is_connected(dns_client_t* client);

#ifdef __cplusplus
}
#endif

#endif // DNS_BLOCKER_CLIENT_H
