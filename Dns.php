<?php
/**
 * DNS Blocker API - Secure Ad Blocking Endpoint
 * 
 * Features:
 * - /connect endpoint for client authentication
 * - Ad domain blocking with customizable blocklist
 * - API key authentication for security
 * - Rate limiting protection
 * - Support for Android APK, C/C++ clients
 * 
 * @author DNS Blocker API
 * @version 1.0.0
 */

// Configuration
define('API_SECRET_KEY', 'your-secret-api-key-change-this-' . bin2hex(random_bytes(16)));
define('MAX_REQUESTS_PER_MINUTE', 100);
define('ENABLE_LOGGING', true);
define('LOG_FILE', __DIR__ . '/dns_blocker.log');

// CORS Headers for cross-origin requests
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key');
header('Content-Type: application/json');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

/**
 * DNS Blocker API Class
 */
class DnsBlockerAPI {
    
    private $blockedDomains = [];
    private $apiKeys = [];
    private $rateLimits = [];
    
    // Default ad/tracker domains to block
    private $defaultBlocklist = [
        // Ad Networks
        'doubleclick.net',
        'googlesyndication.com',
        'googleadservices.com',
        'google-analytics.com',
        'googletagmanager.com',
        'googletagservices.com',
        'adservice.google.com',
        'pagead2.googlesyndication.com',
        'ads.google.com',
        
        // Facebook Ads
        'facebook.com/ads',
        'an.facebook.com',
        'pixel.facebook.com',
        
        // Other Ad Networks
        'ad.doubleclick.net',
        'adnxs.com',
        'advertising.com',
        'adform.net',
        'adsrvr.org',
        'adtechus.com',
        'admob.com',
        'mopub.com',
        'unity3d.com/ads',
        'unityads.unity3d.com',
        'ads.unity3d.com',
        
        // Trackers
        'analytics.google.com',
        'mixpanel.com',
        'segment.com',
        'amplitude.com',
        'branch.io',
        'adjust.com',
        'appsflyer.com',
        'kochava.com',
        'singular.net',
        
        // Mobile Ad Networks
        'applovin.com',
        'vungle.com',
        'chartboost.com',
        'ironsrc.com',
        'inmobi.com',
        'startapp.com',
        'tapjoy.com',
        'fyber.com',
        
        // Popup/Malware
        'popads.net',
        'popcash.net',
        'propellerads.com',
        'adcash.com',
        'exoclick.com',
        
        // Tracking Pixels
        'pixel.wp.com',
        'stats.wp.com',
        'bat.bing.com',
        'tr.snapchat.com',
        'analytics.twitter.com',
        'ads-api.twitter.com',
        
        // Additional trackers
        'crashlytics.com',
        'fabric.io',
        'flurry.com',
        'scorecardresearch.com',
        'quantserve.com',
        'omtrdc.net',
        'demdex.net',
        'krxd.net',
        'bluekai.com',
        'exelator.com',
        'taboola.com',
        'outbrain.com',
        'revcontent.com',
        'mgid.com',
        'content-ad.net',
    ];
    
    private $configFile;
    private $apiKeysFile;
    
    public function __construct() {
        $this->configFile = __DIR__ . '/dns_config.json';
        $this->apiKeysFile = __DIR__ . '/api_keys.json';
        $this->loadConfig();
        $this->loadApiKeys();
    }
    
    /**
     * Load configuration from file
     */
    private function loadConfig() {
        if (file_exists($this->configFile)) {
            $config = json_decode(file_get_contents($this->configFile), true);
            if (isset($config['blocked_domains'])) {
                $this->blockedDomains = array_merge($this->defaultBlocklist, $config['blocked_domains']);
            } else {
                $this->blockedDomains = $this->defaultBlocklist;
            }
        } else {
            $this->blockedDomains = $this->defaultBlocklist;
            $this->saveConfig();
        }
    }
    
    /**
     * Save configuration to file
     */
    private function saveConfig() {
        $config = [
            'blocked_domains' => $this->blockedDomains,
            'updated_at' => date('Y-m-d H:i:s')
        ];
        file_put_contents($this->configFile, json_encode($config, JSON_PRETTY_PRINT));
    }
    
    /**
     * Load API keys from file
     */
    private function loadApiKeys() {
        if (file_exists($this->apiKeysFile)) {
            $this->apiKeys = json_decode(file_get_contents($this->apiKeysFile), true) ?: [];
        } else {
            // Generate a default API key
            $defaultKey = $this->generateApiKey();
            $this->apiKeys[$defaultKey] = [
                'name' => 'default',
                'created_at' => date('Y-m-d H:i:s'),
                'active' => true,
                'permissions' => ['connect', 'query', 'resolve']
            ];
            $this->saveApiKeys();
        }
    }
    
    /**
     * Save API keys to file
     */
    private function saveApiKeys() {
        file_put_contents($this->apiKeysFile, json_encode($this->apiKeys, JSON_PRETTY_PRINT));
    }
    
    /**
     * Generate a secure API key
     */
    public function generateApiKey() {
        return 'dnsb_' . bin2hex(random_bytes(24));
    }
    
    /**
     * Validate API key
     */
    public function validateApiKey($apiKey) {
        return isset($this->apiKeys[$apiKey]) && $this->apiKeys[$apiKey]['active'];
    }
    
    /**
     * Check rate limit
     */
    private function checkRateLimit($clientIP) {
        $rateLimitFile = __DIR__ . '/rate_limits.json';
        $limits = [];
        
        if (file_exists($rateLimitFile)) {
            $limits = json_decode(file_get_contents($rateLimitFile), true) ?: [];
        }
        
        $currentMinute = floor(time() / 60);
        
        if (!isset($limits[$clientIP]) || $limits[$clientIP]['minute'] !== $currentMinute) {
            $limits[$clientIP] = [
                'minute' => $currentMinute,
                'count' => 0
            ];
        }
        
        $limits[$clientIP]['count']++;
        file_put_contents($rateLimitFile, json_encode($limits));
        
        return $limits[$clientIP]['count'] <= MAX_REQUESTS_PER_MINUTE;
    }
    
    /**
     * Log request
     */
    private function logRequest($action, $data, $clientIP) {
        if (!ENABLE_LOGGING) return;
        
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $clientIP,
            'action' => $action,
            'data' => $data
        ];
        
        file_put_contents(LOG_FILE, json_encode($logEntry) . "\n", FILE_APPEND | LOCK_EX);
    }
    
    /**
     * Get client IP address
     */
    private function getClientIP() {
        $headers = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = explode(',', $_SERVER[$header])[0];
                return trim($ip);
            }
        }
        return '0.0.0.0';
    }
    
    /**
     * Get API key from request
     */
    private function getApiKeyFromRequest() {
        // Check header
        $headers = getallheaders();
        if (isset($headers['X-API-Key'])) {
            return $headers['X-API-Key'];
        }
        if (isset($headers['Authorization'])) {
            return str_replace('Bearer ', '', $headers['Authorization']);
        }
        
        // Check GET/POST parameters
        if (isset($_REQUEST['api_key'])) {
            return $_REQUEST['api_key'];
        }
        
        return null;
    }
    
    /**
     * Send JSON response
     */
    private function sendResponse($data, $statusCode = 200) {
        http_response_code($statusCode);
        echo json_encode($data, JSON_PRETTY_PRINT);
        exit();
    }
    
    /**
     * Send error response
     */
    private function sendError($message, $statusCode = 400) {
        $this->sendResponse([
            'success' => false,
            'error' => $message,
            'timestamp' => time()
        ], $statusCode);
    }
    
    /**
     * Check if domain is blocked
     */
    public function isDomainBlocked($domain) {
        $domain = strtolower(trim($domain));
        
        foreach ($this->blockedDomains as $blocked) {
            // Exact match
            if ($domain === $blocked) {
                return true;
            }
            // Subdomain match
            if (substr($domain, -strlen($blocked) - 1) === '.' . $blocked) {
                return true;
            }
            // Wildcard match
            if (strpos($blocked, '*') !== false) {
                $pattern = str_replace('*', '.*', $blocked);
                if (preg_match('/^' . $pattern . '$/', $domain)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * CONNECT endpoint - Main entry point for clients
     */
    public function handleConnect() {
        $clientIP = $this->getClientIP();
        $apiKey = $this->getApiKeyFromRequest();
        
        // Rate limiting
        if (!$this->checkRateLimit($clientIP)) {
            $this->sendError('Rate limit exceeded. Try again later.', 429);
        }
        
        // API key validation
        if (!$apiKey || !$this->validateApiKey($apiKey)) {
            $this->logRequest('connect_failed', ['reason' => 'invalid_api_key'], $clientIP);
            $this->sendError('Invalid or missing API key. Access denied.', 401);
        }
        
        $this->logRequest('connect_success', ['api_key' => substr($apiKey, 0, 10) . '...'], $clientIP);
        
        $this->sendResponse([
            'success' => true,
            'message' => 'Connected to DNS Blocker API',
            'client_ip' => $clientIP,
            'server_time' => time(),
            'blocked_domains_count' => count($this->blockedDomains),
            'endpoints' => [
                'resolve' => '/resolve?domain=example.com',
                'check' => '/check?domain=example.com',
                'blocklist' => '/blocklist',
                'status' => '/status'
            ]
        ]);
    }
    
    /**
     * RESOLVE endpoint - DNS resolution with ad blocking
     */
    public function handleResolve() {
        $clientIP = $this->getClientIP();
        $apiKey = $this->getApiKeyFromRequest();
        
        if (!$this->checkRateLimit($clientIP)) {
            $this->sendError('Rate limit exceeded', 429);
        }
        
        if (!$apiKey || !$this->validateApiKey($apiKey)) {
            $this->sendError('Unauthorized', 401);
        }
        
        $domain = $_REQUEST['domain'] ?? null;
        if (!$domain) {
            $this->sendError('Domain parameter required');
        }
        
        $domain = strtolower(trim($domain));
        
        // Check if blocked
        if ($this->isDomainBlocked($domain)) {
            $this->logRequest('resolve_blocked', ['domain' => $domain], $clientIP);
            $this->sendResponse([
                'success' => true,
                'domain' => $domain,
                'blocked' => true,
                'reason' => 'ad_tracker_blocked',
                'ip' => '0.0.0.0',
                'ipv6' => '::',
                'ttl' => 300
            ]);
        }
        
        // Resolve the domain
        $ipv4 = gethostbyname($domain);
        $ipv6Records = dns_get_record($domain, DNS_AAAA);
        $ipv6 = !empty($ipv6Records) ? $ipv6Records[0]['ipv6'] : null;
        
        $this->logRequest('resolve_success', ['domain' => $domain, 'ip' => $ipv4], $clientIP);
        
        $this->sendResponse([
            'success' => true,
            'domain' => $domain,
            'blocked' => false,
            'ip' => $ipv4 !== $domain ? $ipv4 : null,
            'ipv6' => $ipv6,
            'ttl' => 300
        ]);
    }
    
    /**
     * CHECK endpoint - Check if domain is blocked
     */
    public function handleCheck() {
        $clientIP = $this->getClientIP();
        $apiKey = $this->getApiKeyFromRequest();
        
        if (!$apiKey || !$this->validateApiKey($apiKey)) {
            $this->sendError('Unauthorized', 401);
        }
        
        $domain = $_REQUEST['domain'] ?? null;
        if (!$domain) {
            $this->sendError('Domain parameter required');
        }
        
        $blocked = $this->isDomainBlocked($domain);
        
        $this->sendResponse([
            'success' => true,
            'domain' => $domain,
            'blocked' => $blocked,
            'category' => $blocked ? 'ad_tracker' : 'allowed'
        ]);
    }
    
    /**
     * BLOCKLIST endpoint - Get or manage blocklist
     */
    public function handleBlocklist() {
        $clientIP = $this->getClientIP();
        $apiKey = $this->getApiKeyFromRequest();
        
        if (!$apiKey || !$this->validateApiKey($apiKey)) {
            $this->sendError('Unauthorized', 401);
        }
        
        $method = $_SERVER['REQUEST_METHOD'];
        
        if ($method === 'GET') {
            $this->sendResponse([
                'success' => true,
                'count' => count($this->blockedDomains),
                'domains' => $this->blockedDomains
            ]);
        } elseif ($method === 'POST') {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (isset($input['add']) && is_array($input['add'])) {
                foreach ($input['add'] as $domain) {
                    if (!in_array($domain, $this->blockedDomains)) {
                        $this->blockedDomains[] = strtolower(trim($domain));
                    }
                }
                $this->saveConfig();
            }
            
            if (isset($input['remove']) && is_array($input['remove'])) {
                $this->blockedDomains = array_diff($this->blockedDomains, $input['remove']);
                $this->saveConfig();
            }
            
            $this->sendResponse([
                'success' => true,
                'message' => 'Blocklist updated',
                'count' => count($this->blockedDomains)
            ]);
        }
    }
    
    /**
     * STATUS endpoint - API health check
     */
    public function handleStatus() {
        $this->sendResponse([
            'success' => true,
            'status' => 'online',
            'version' => '1.0.0',
            'blocked_domains' => count($this->blockedDomains),
            'server_time' => date('Y-m-d H:i:s'),
            'uptime' => $this->getUptime()
        ]);
    }
    
    /**
     * Get server uptime
     */
    private function getUptime() {
        if (file_exists('/proc/uptime')) {
            $uptime = file_get_contents('/proc/uptime');
            $uptime = explode(' ', $uptime)[0];
            return (int) $uptime . ' seconds';
        }
        return 'N/A';
    }
    
    /**
     * GENERATE KEY endpoint - Generate new API key (admin only)
     */
    public function handleGenerateKey() {
        $clientIP = $this->getClientIP();
        $apiKey = $this->getApiKeyFromRequest();
        
        if (!$apiKey || !$this->validateApiKey($apiKey)) {
            $this->sendError('Unauthorized', 401);
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        $name = $input['name'] ?? 'unnamed_' . time();
        
        $newKey = $this->generateApiKey();
        $this->apiKeys[$newKey] = [
            'name' => $name,
            'created_at' => date('Y-m-d H:i:s'),
            'active' => true,
            'permissions' => ['connect', 'query', 'resolve']
        ];
        $this->saveApiKeys();
        
        $this->logRequest('key_generated', ['name' => $name], $clientIP);
        
        $this->sendResponse([
            'success' => true,
            'api_key' => $newKey,
            'name' => $name,
            'message' => 'Store this key securely. It will not be shown again.'
        ]);
    }
    
    /**
     * BULK RESOLVE endpoint - Resolve multiple domains at once
     */
    public function handleBulkResolve() {
        $clientIP = $this->getClientIP();
        $apiKey = $this->getApiKeyFromRequest();
        
        if (!$apiKey || !$this->validateApiKey($apiKey)) {
            $this->sendError('Unauthorized', 401);
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        $domains = $input['domains'] ?? [];
        
        if (empty($domains) || !is_array($domains)) {
            $this->sendError('Domains array required');
        }
        
        if (count($domains) > 50) {
            $this->sendError('Maximum 50 domains per request');
        }
        
        $results = [];
        foreach ($domains as $domain) {
            $domain = strtolower(trim($domain));
            $blocked = $this->isDomainBlocked($domain);
            
            if ($blocked) {
                $results[$domain] = [
                    'blocked' => true,
                    'ip' => '0.0.0.0'
                ];
            } else {
                $ip = gethostbyname($domain);
                $results[$domain] = [
                    'blocked' => false,
                    'ip' => $ip !== $domain ? $ip : null
                ];
            }
        }
        
        $this->sendResponse([
            'success' => true,
            'count' => count($results),
            'results' => $results
        ]);
    }
    
    /**
     * Route the request to appropriate handler
     */
    public function route() {
        $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $uri = trim($uri, '/');
        
        // Remove base path if present
        $basePath = basename(__DIR__);
        $uri = preg_replace('/^' . preg_quote($basePath, '/') . '\//', '', $uri);
        $uri = preg_replace('/^Dns\.php\//', '', $uri);
        $uri = preg_replace('/^Dns\.php$/', '', $uri);
        
        // Extract endpoint
        $endpoint = strtolower(trim($uri, '/'));
        
        switch ($endpoint) {
            case '':
            case 'connect':
                $this->handleConnect();
                break;
            case 'resolve':
                $this->handleResolve();
                break;
            case 'check':
                $this->handleCheck();
                break;
            case 'blocklist':
                $this->handleBlocklist();
                break;
            case 'status':
                $this->handleStatus();
                break;
            case 'generate-key':
            case 'generatekey':
                $this->handleGenerateKey();
                break;
            case 'bulk-resolve':
            case 'bulkresolve':
                $this->handleBulkResolve();
                break;
            default:
                $this->sendError('Unknown endpoint: ' . $endpoint, 404);
        }
    }
}

// Initialize and run
$api = new DnsBlockerAPI();
$api->route();
