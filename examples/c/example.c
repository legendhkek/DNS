/**
 * DNS Blocker Client Example - C/C++
 * 
 * Compile:
 *   gcc -o dns_example example.c dns_blocker_client.c -lcurl
 * 
 * Run:
 *   ./dns_example
 */

#include <stdio.h>
#include "dns_blocker_client.h"

int main(int argc, char* argv[]) {
    // Configuration - CHANGE THESE VALUES
    const char* server_url = "https://your-server.com/Dns.php";
    const char* api_key = "your-api-key-here";
    
    printf("=== DNS Blocker Client Example ===\n\n");
    
    // Initialize client
    dns_client_t* client = dns_client_init(server_url, api_key);
    if (!client) {
        printf("Failed to initialize client\n");
        return 1;
    }
    
    printf("Connecting to DNS Blocker API...\n");
    
    // Connect
    if (!dns_client_connect(client)) {
        printf("Connection failed: %s\n", dns_client_get_error(client));
        dns_client_free(client);
        return 1;
    }
    
    printf("Connected successfully!\n\n");
    
    // Get status
    dns_status_t status;
    if (dns_client_status(client, &status)) {
        printf("Server Status:\n");
        printf("  - Online: %s\n", status.online ? "Yes" : "No");
        printf("  - Version: %s\n", status.version);
        printf("  - Blocked domains: %d\n", status.blocked_domains_count);
        printf("  - Server time: %s\n\n", status.server_time);
    }
    
    // Test domains
    const char* test_domains[] = {
        "google.com",           // Should NOT be blocked
        "doubleclick.net",      // Should be blocked (ad network)
        "github.com",           // Should NOT be blocked
        "googlesyndication.com", // Should be blocked (ads)
        "facebook.com",         // Should NOT be blocked
        "an.facebook.com",      // Should be blocked (FB ads)
        NULL
    };
    
    printf("Testing domain resolution:\n");
    printf("--------------------------\n");
    
    for (int i = 0; test_domains[i] != NULL; i++) {
        dns_result_t result;
        
        if (dns_client_resolve(client, test_domains[i], &result)) {
            if (result.blocked) {
                printf("  [BLOCKED] %s -> 0.0.0.0 (ad/tracker blocked)\n", result.domain);
            } else {
                printf("  [ALLOWED] %s -> %s\n", result.domain, 
                       result.ip[0] ? result.ip : "N/A");
            }
        } else {
            printf("  [ERROR] %s: %s\n", test_domains[i], dns_client_get_error(client));
        }
    }
    
    printf("\n");
    
    // Quick check example
    printf("Quick block check:\n");
    printf("  ads.google.com is %s\n", 
           dns_client_is_blocked(client, "ads.google.com") ? "BLOCKED" : "allowed");
    printf("  stackoverflow.com is %s\n", 
           dns_client_is_blocked(client, "stackoverflow.com") ? "BLOCKED" : "allowed");
    
    // Cleanup
    dns_client_free(client);
    
    printf("\nDone!\n");
    return 0;
}
