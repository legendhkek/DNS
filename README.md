# DNS Blocker API

A secure DNS blocking API endpoint that blocks ads and trackers for your applications. Works with Android APK, C, and C++ projects.

## Features

- 🛡️ **Ad Blocking** - Blocks 100+ known ad networks and trackers
- 🔐 **API Key Authentication** - Secure access with unique API keys
- 🚀 **Fast Resolution** - Lightweight DNS resolution with blocking
- 📱 **Multi-Platform** - Client libraries for Android, C, and C++
- 🔄 **Rate Limiting** - Built-in protection against abuse
- 📝 **Logging** - Request logging for monitoring
- ⚙️ **Customizable** - Add/remove domains from blocklist

## Quick Start

### 1. Deploy the API

Upload `Dns.php` to your PHP-enabled web server:

```bash
# Example: Upload to your server
scp Dns.php user@your-server.com:/var/www/html/
```

### 2. Get Your API Key

On first run, the API generates a default API key. Check the `api_keys.json` file:

```bash
cat api_keys.json
```

Example output:
```json
{
    "dnsb_a1b2c3d4e5f6...": {
        "name": "default",
        "created_at": "2024-01-01 12:00:00",
        "active": true,
        "permissions": ["connect", "query", "resolve"]
    }
}
```

### 3. Test the API

```bash
# Test connection
curl -H "X-API-Key: YOUR_API_KEY" https://your-server.com/Dns.php/connect

# Check if domain is blocked
curl -H "X-API-Key: YOUR_API_KEY" "https://your-server.com/Dns.php/check?domain=doubleclick.net"

# Resolve domain
curl -H "X-API-Key: YOUR_API_KEY" "https://your-server.com/Dns.php/resolve?domain=google.com"
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/connect` | GET | Authenticate and connect to API |
| `/resolve?domain=` | GET | Resolve domain with ad blocking |
| `/check?domain=` | GET | Check if domain is blocked |
| `/blocklist` | GET | Get list of blocked domains |
| `/blocklist` | POST | Add/remove domains from blocklist |
| `/status` | GET | API health check |
| `/bulk-resolve` | POST | Resolve multiple domains at once |
| `/generate-key` | POST | Generate new API key |

## Client Integration

### Android (Java)

```java
// Initialize client
DnsBlockerClient client = new DnsBlockerClient(
    "https://your-server.com/Dns.php", 
    "your-api-key"
);

// Connect
client.connect(new DnsBlockerClient.Callback() {
    @Override
    public void onSuccess(JSONObject response) {
        Log.d("DNS", "Connected! Blocked domains: " + 
              response.optInt("blocked_domains_count"));
    }
    
    @Override
    public void onError(String error) {
        Log.e("DNS", "Connection failed: " + error);
    }
});

// Resolve domain with ad blocking
client.resolve("doubleclick.net", new DnsBlockerClient.ResolveCallback() {
    @Override
    public void onResolved(String domain, String ip, boolean blocked) {
        if (blocked) {
            // Domain is an ad/tracker - block it!
            Log.d("DNS", "Blocked: " + domain);
        } else {
            // Safe domain - use the IP
            Log.d("DNS", "Resolved: " + domain + " -> " + ip);
        }
    }
    
    @Override
    public void onError(String error) {
        Log.e("DNS", "Error: " + error);
    }
});
```

### C

```c
#include "dns_blocker_client.h"

int main() {
    // Initialize
    dns_client_t* client = dns_client_init(
        "https://your-server.com/Dns.php",
        "your-api-key"
    );
    
    // Connect
    if (dns_client_connect(client)) {
        printf("Connected!\n");
        
        // Check if domain is blocked
        if (dns_client_is_blocked(client, "doubleclick.net")) {
            printf("Domain is blocked (ad/tracker)\n");
        }
        
        // Resolve domain
        dns_result_t result;
        if (dns_client_resolve(client, "google.com", &result)) {
            if (result.blocked) {
                printf("Blocked: %s\n", result.domain);
            } else {
                printf("Resolved: %s -> %s\n", result.domain, result.ip);
            }
        }
    }
    
    // Cleanup
    dns_client_free(client);
    return 0;
}
```

Compile:
```bash
gcc -o myapp myapp.c dns_blocker_client.c -lcurl
```

### C++

```cpp
#include "DnsBlockerClient.hpp"

int main() {
    // Create client
    DnsBlocker::Client client(
        "https://your-server.com/Dns.php",
        "your-api-key"
    );
    
    // Connect
    auto connInfo = client.connect();
    if (connInfo.success) {
        std::cout << "Connected! IP: " << connInfo.clientIp << "\n";
        
        // Resolve domain
        auto result = client.resolve("doubleclick.net");
        if (result.blocked) {
            std::cout << "Blocked: " << result.domain << "\n";
        } else {
            std::cout << "Resolved: " << result.domain << " -> " << result.ip << "\n";
        }
        
        // Bulk resolve
        auto results = client.bulkResolve({"google.com", "admob.com", "github.com"});
        for (const auto& [domain, res] : results) {
            std::cout << domain << ": " << (res.blocked ? "BLOCKED" : "allowed") << "\n";
        }
    }
    
    return 0;
}
```

Compile:
```bash
g++ -std=c++17 -o myapp main.cpp DnsBlockerClient.cpp -lcurl
```

## Security Features

### API Key Authentication

Every request must include your API key:

```bash
# Header method (recommended)
curl -H "X-API-Key: YOUR_API_KEY" https://your-server.com/Dns.php/connect

# Authorization header
curl -H "Authorization: Bearer YOUR_API_KEY" https://your-server.com/Dns.php/connect

# Query parameter (less secure)
curl "https://your-server.com/Dns.php/connect?api_key=YOUR_API_KEY"
```

### Generate New API Keys

```bash
curl -X POST \
  -H "X-API-Key: YOUR_EXISTING_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-android-app"}' \
  https://your-server.com/Dns.php/generate-key
```

### Rate Limiting

- Default: 100 requests per minute per IP
- Configurable in `Dns.php` (`MAX_REQUESTS_PER_MINUTE`)

## Blocked Domains

The API blocks 100+ known ad networks and trackers including:

- **Google Ads**: doubleclick.net, googlesyndication.com, googleadservices.com
- **Facebook Ads**: an.facebook.com, pixel.facebook.com
- **Mobile Ads**: admob.com, unityads.unity3d.com, applovin.com, vungle.com
- **Trackers**: google-analytics.com, mixpanel.com, amplitude.com
- **And many more...**

### Customize Blocklist

Add domains:
```bash
curl -X POST \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"add": ["custom-ad-domain.com", "another-tracker.net"]}' \
  https://your-server.com/Dns.php/blocklist
```

Remove domains:
```bash
curl -X POST \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"remove": ["domain-to-allow.com"]}' \
  https://your-server.com/Dns.php/blocklist
```

## Response Examples

### Connect Response
```json
{
    "success": true,
    "message": "Connected to DNS Blocker API",
    "client_ip": "203.0.113.1",
    "server_time": 1704067200,
    "blocked_domains_count": 105,
    "endpoints": {
        "resolve": "/resolve?domain=example.com",
        "check": "/check?domain=example.com",
        "blocklist": "/blocklist",
        "status": "/status"
    }
}
```

### Resolve Response (Blocked)
```json
{
    "success": true,
    "domain": "doubleclick.net",
    "blocked": true,
    "reason": "ad_tracker_blocked",
    "ip": "0.0.0.0",
    "ipv6": "::",
    "ttl": 300
}
```

### Resolve Response (Allowed)
```json
{
    "success": true,
    "domain": "google.com",
    "blocked": false,
    "ip": "142.250.80.46",
    "ipv6": "2607:f8b0:4004:800::200e",
    "ttl": 300
}
```

## Server Requirements

- PHP 7.4+ with:
  - curl extension
  - json extension
- Write permissions for config files
- HTTPS recommended for production

## Files

```
/workspace/
├── Dns.php                          # Main API endpoint
├── README.md                        # This file
└── examples/
    ├── android/
    │   ├── DnsBlockerClient.java    # Android client library
    │   └── MainActivity.java        # Usage example
    ├── c/
    │   ├── dns_blocker_client.h     # C header
    │   ├── dns_blocker_client.c     # C implementation
    │   └── example.c                # Usage example
    └── cpp/
        ├── DnsBlockerClient.hpp     # C++ header
        ├── DnsBlockerClient.cpp     # C++ implementation
        └── example.cpp              # Usage example
```

## License

MIT License - Use freely in your projects.

## Support

For issues or questions, create an issue in the repository.
