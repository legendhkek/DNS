<?php
/**
 * Stealth DNS Service API
 * 
 * Features:
 * - Encrypted request/response
 * - Obfuscated endpoints (looks like normal API)
 * - Anti-detection measures
 * - Dynamic response headers
 * - Binary protocol option
 * 
 * @version 2.0.0
 */

// ==================== CONFIGURATION ====================

// Secret key for encryption (CHANGE THIS!)
define('SECRET_KEY', 'your-32-char-secret-key-here!!!');

// Enable stealth mode
define('STEALTH_MODE', true);

// Fake service name (appears in responses)
define('SERVICE_NAME', 'CloudSync API');
define('SERVICE_VERSION', '3.2.1');

// Rate limiting
define('MAX_REQUESTS_PER_MINUTE', 200);

// ==================== STEALTH HEADERS ====================

// Randomize response headers to look like different services
$fakeHeaders = [
    ['Server' => 'nginx/1.18.0', 'X-Powered-By' => 'Express'],
    ['Server' => 'Apache/2.4.41', 'X-Powered-By' => 'PHP/7.4.3'],
    ['Server' => 'cloudflare', 'CF-RAY' => bin2hex(random_bytes(8))],
    ['Server' => 'AmazonS3', 'x-amz-request-id' => strtoupper(bin2hex(random_bytes(8)))],
    ['Server' => 'gws', 'X-XSS-Protection' => '0'],
];

$selectedHeaders = $fakeHeaders[array_rand($fakeHeaders)];
foreach ($selectedHeaders as $name => $value) {
    header("$name: $value");
}

header('Content-Type: application/json');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Content-Type-Options: nosniff');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Token, X-Request-ID');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit();
}

// ==================== ENCRYPTION ====================

class Crypto {
    private static $method = 'AES-256-GCM';
    
    public static function encrypt($data, $key = SECRET_KEY) {
        $iv = random_bytes(12);
        $tag = '';
        $encrypted = openssl_encrypt(
            json_encode($data),
            self::$method,
            hash('sha256', $key, true),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            16
        );
        return base64_encode($iv . $tag . $encrypted);
    }
    
    public static function decrypt($data, $key = SECRET_KEY) {
        $raw = base64_decode($data);
        if (strlen($raw) < 28) return null;
        
        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $encrypted = substr($raw, 28);
        
        $decrypted = openssl_decrypt(
            $encrypted,
            self::$method,
            hash('sha256', $key, true),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        return $decrypted ? json_decode($decrypted, true) : null;
    }
    
    // Simple XOR obfuscation for lightweight encoding
    public static function xorEncode($data, $key = SECRET_KEY) {
        $keyLen = strlen($key);
        $result = '';
        for ($i = 0; $i < strlen($data); $i++) {
            $result .= $data[$i] ^ $key[$i % $keyLen];
        }
        return base64_encode($result);
    }
    
    public static function xorDecode($data, $key = SECRET_KEY) {
        $raw = base64_decode($data);
        $keyLen = strlen($key);
        $result = '';
        for ($i = 0; $i < strlen($raw); $i++) {
            $result .= $raw[$i] ^ $key[$i % $keyLen];
        }
        return $result;
    }
    
    // Generate auth token
    public static function generateToken($clientId) {
        $payload = [
            'id' => $clientId,
            'ts' => time(),
            'rnd' => bin2hex(random_bytes(8))
        ];
        return self::encrypt($payload);
    }
    
    // Verify auth token
    public static function verifyToken($token, $maxAge = 86400) {
        $payload = self::decrypt($token);
        if (!$payload) return false;
        if (!isset($payload['ts'])) return false;
        if (time() - $payload['ts'] > $maxAge) return false;
        return $payload;
    }
}

// ==================== STEALTH SERVICE ====================

class StealthService {
    
    private $configFile;
    private $tokensFile;
    private $blocklist = [];
    
    // Obfuscated blocklist (encoded domain patterns)
    private $encodedPatterns = [
        'ZG91YmxlY2xpY2s=', 'Z29vZ2xlc3luZGljYXRpb24=', 'Z29vZ2xlYWRzZXJ2aWNlcw==',
        'Z29vZ2xlLWFuYWx5dGljcw==', 'Z29vZ2xldGFnbWFuYWdlcg==', 'YWRzZXJ2aWNl',
        'cGFnZWFk', 'YWRtb2I=', 'YWRzZW5zZQ==', 'YWRueHM=', 'YWR2ZXJ0aXNpbmc=',
        'bW9wdWI=', 'dW5pdHlhZHM=', 'YXBwbG92aW4=', 'dnVuZ2xl', 'Y2hhcnRib29zdA==',
        'aXJvbnNyYw==', 'aW5tb2Jp', 'dGFwam95', 'ZnliZXI=', 'YW4uZmFjZWJvb2s=',
        'cGl4ZWwuZmFjZWJvb2s=', 'YW5hbHl0aWNz', 'dHJhY2tlcg==', 'dHJhY2tpbmc=',
        'dGVsZW1ldHJ5', 'bWl4cGFuZWw=', 'c2VnbWVudC5jb20=', 'YW1wbGl0dWRl',
        'YnJhbmNoLmlv', 'YWRqdXN0LmNvbQ==', 'YXBwc2ZseWVy', 'a29jaGF2YQ==',
        'cG9wYWRz', 'cG9wY2FzaA==', 'cHJvcGVsbGVyYWRz', 'dGFib29sYQ==',
        'b3V0YnJhaW4=', 'cmV2Y29udGVudA==', 'bWdpZA==', 'Y3Jhc2hseXRpY3M=',
        'Zmx1cnJ5', 'c2NvcmVjYXJkcmVzZWFyY2g=', 'cXVhbnRzZXJ2ZQ==',
        'ZGVtZGV4', 'a3J4ZA==', 'Ymx1ZWthaQ==', 'ZXhlbGF0b3I='
    ];
    
    public function __construct() {
        $this->configFile = __DIR__ . '/.cfg_' . substr(md5(SECRET_KEY), 0, 8);
        $this->tokensFile = __DIR__ . '/.tkn_' . substr(md5(SECRET_KEY), 0, 8);
        $this->loadConfig();
    }
    
    private function loadConfig() {
        // Decode patterns
        foreach ($this->encodedPatterns as $encoded) {
            $this->blocklist[] = base64_decode($encoded);
        }
        
        // Load custom config if exists
        if (file_exists($this->configFile)) {
            $data = Crypto::decrypt(file_get_contents($this->configFile));
            if ($data && isset($data['custom'])) {
                $this->blocklist = array_merge($this->blocklist, $data['custom']);
            }
        }
    }
    
    private function saveConfig($customDomains) {
        $data = Crypto::encrypt(['custom' => $customDomains, 'updated' => time()]);
        file_put_contents($this->configFile, $data);
    }
    
    // ==================== DETECTION ====================
    
    private function isTarget($domain) {
        $domain = strtolower(trim($domain));
        
        foreach ($this->blocklist as $pattern) {
            if (strpos($domain, $pattern) !== false) {
                return true;
            }
        }
        
        // Check subdomains
        $parts = explode('.', $domain);
        while (count($parts) > 1) {
            array_shift($parts);
            $parent = implode('.', $parts);
            foreach ($this->blocklist as $pattern) {
                if ($parent === $pattern || strpos($parent, $pattern) !== false) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    // ==================== REQUEST HANDLING ====================
    
    private function getClientIP() {
        $headers = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                return trim(explode(',', $_SERVER[$header])[0]);
            }
        }
        return '0.0.0.0';
    }
    
    private function getAuthToken() {
        $headers = getallheaders();
        // Check multiple header names (stealth)
        $tokenHeaders = ['X-Token', 'Authorization', 'X-Request-ID', 'X-Session'];
        foreach ($tokenHeaders as $h) {
            if (isset($headers[$h])) {
                $value = $headers[$h];
                $value = str_replace('Bearer ', '', $value);
                return $value;
            }
        }
        // Check query/post params
        foreach (['t', 'token', 'key', 'sid'] as $param) {
            if (isset($_REQUEST[$param])) {
                return $_REQUEST[$param];
            }
        }
        return null;
    }
    
    private function authenticate() {
        $token = $this->getAuthToken();
        if (!$token) {
            return $this->generateNewToken();
        }
        
        $payload = Crypto::verifyToken($token);
        if (!$payload) {
            return $this->generateNewToken();
        }
        
        return ['valid' => true, 'payload' => $payload];
    }
    
    private function generateNewToken() {
        $clientId = md5($this->getClientIP() . $_SERVER['HTTP_USER_AGENT'] ?? '');
        $token = Crypto::generateToken($clientId);
        return ['valid' => true, 'new_token' => $token, 'payload' => ['id' => $clientId]];
    }
    
    // ==================== RESPONSES ====================
    
    private function respond($data, $encrypted = true, $status = 200) {
        http_response_code($status);
        
        if (STEALTH_MODE && $encrypted) {
            // Wrap in fake API response
            $response = [
                'status' => 'success',
                'service' => SERVICE_NAME,
                'version' => SERVICE_VERSION,
                'data' => Crypto::encrypt($data),
                'ts' => time()
            ];
        } else {
            $response = $data;
        }
        
        echo json_encode($response);
        exit();
    }
    
    private function respondError($message, $status = 400) {
        http_response_code($status);
        echo json_encode([
            'status' => 'error',
            'service' => SERVICE_NAME,
            'message' => STEALTH_MODE ? 'Request failed' : $message,
            'code' => $status
        ]);
        exit();
    }
    
    // ==================== ENDPOINTS ====================
    
    // Obfuscated endpoint names (look like normal API)
    private $endpoints = [
        'init' => ['i', 'init', 'start', 'begin', 'handshake'],
        'query' => ['q', 'query', 'lookup', 'find', 'search', 'get'],
        'check' => ['c', 'check', 'verify', 'validate', 'test'],
        'batch' => ['b', 'batch', 'bulk', 'multi', 'list'],
        'sync' => ['s', 'sync', 'update', 'refresh', 'pull'],
        'status' => ['st', 'status', 'health', 'ping', 'info'],
        'config' => ['cfg', 'config', 'settings', 'prefs'],
    ];
    
    private function matchEndpoint($path, $type) {
        $path = strtolower(trim($path, '/'));
        return in_array($path, $this->endpoints[$type]);
    }
    
    public function handleInit() {
        $auth = $this->authenticate();
        
        $response = [
            'ok' => true,
            'token' => $auth['new_token'] ?? null,
            'cid' => $auth['payload']['id'] ?? null,
            'ts' => time(),
            'cfg' => [
                'ttl' => 300,
                'batch_max' => 50,
                'endpoints' => [
                    'q' => '/q',
                    'c' => '/c', 
                    'b' => '/b',
                    's' => '/s'
                ]
            ],
            'cnt' => count($this->blocklist)
        ];
        
        $this->respond($response);
    }
    
    public function handleQuery() {
        $auth = $this->authenticate();
        if (!$auth['valid']) {
            $this->respondError('Unauthorized', 401);
        }
        
        // Get domain from various params (stealth)
        $domain = null;
        foreach (['d', 'domain', 'host', 'target', 'url', 'q'] as $param) {
            if (isset($_REQUEST[$param])) {
                $domain = $_REQUEST[$param];
                break;
            }
        }
        
        // Or from encrypted body
        if (!$domain) {
            $body = file_get_contents('php://input');
            if ($body) {
                $decoded = Crypto::decrypt($body);
                if ($decoded && isset($decoded['d'])) {
                    $domain = $decoded['d'];
                }
            }
        }
        
        if (!$domain) {
            $this->respondError('Missing parameter', 400);
        }
        
        $domain = strtolower(trim($domain));
        $isTarget = $this->isTarget($domain);
        
        if ($isTarget) {
            $response = [
                'ok' => true,
                'd' => $domain,
                'r' => 1,  // result: 1 = blocked
                'ip' => '0.0.0.0',
                'ip6' => '::',
                'ttl' => 300
            ];
        } else {
            // Resolve actual IP
            $ip4 = gethostbyname($domain);
            $ip6Records = @dns_get_record($domain, DNS_AAAA);
            $ip6 = !empty($ip6Records) ? $ip6Records[0]['ipv6'] : null;
            
            $response = [
                'ok' => true,
                'd' => $domain,
                'r' => 0,  // result: 0 = allowed
                'ip' => ($ip4 !== $domain) ? $ip4 : null,
                'ip6' => $ip6,
                'ttl' => 300
            ];
        }
        
        $this->respond($response);
    }
    
    public function handleCheck() {
        $auth = $this->authenticate();
        
        $domain = $_REQUEST['d'] ?? $_REQUEST['domain'] ?? null;
        if (!$domain) {
            $this->respondError('Missing parameter', 400);
        }
        
        $response = [
            'ok' => true,
            'd' => $domain,
            'r' => $this->isTarget($domain) ? 1 : 0
        ];
        
        $this->respond($response);
    }
    
    public function handleBatch() {
        $auth = $this->authenticate();
        
        $body = file_get_contents('php://input');
        $data = null;
        
        // Try encrypted first
        $data = Crypto::decrypt($body);
        if (!$data) {
            $data = json_decode($body, true);
        }
        
        $domains = $data['domains'] ?? $data['d'] ?? $data['list'] ?? [];
        
        if (empty($domains) || !is_array($domains)) {
            $this->respondError('Invalid request', 400);
        }
        
        if (count($domains) > 50) {
            $domains = array_slice($domains, 0, 50);
        }
        
        $results = [];
        foreach ($domains as $domain) {
            $domain = strtolower(trim($domain));
            $isTarget = $this->isTarget($domain);
            
            $results[$domain] = [
                'r' => $isTarget ? 1 : 0,
                'ip' => $isTarget ? '0.0.0.0' : null
            ];
            
            if (!$isTarget) {
                $ip = gethostbyname($domain);
                $results[$domain]['ip'] = ($ip !== $domain) ? $ip : null;
            }
        }
        
        $this->respond([
            'ok' => true,
            'cnt' => count($results),
            'res' => $results
        ]);
    }
    
    public function handleSync() {
        $auth = $this->authenticate();
        
        $method = $_SERVER['REQUEST_METHOD'];
        
        if ($method === 'GET') {
            // Return encoded blocklist
            $encoded = array_map('base64_encode', $this->blocklist);
            $this->respond([
                'ok' => true,
                'cnt' => count($encoded),
                'data' => $encoded
            ]);
        } else if ($method === 'POST') {
            $body = file_get_contents('php://input');
            $data = Crypto::decrypt($body) ?? json_decode($body, true);
            
            if (isset($data['add'])) {
                $custom = [];
                foreach ($data['add'] as $d) {
                    $custom[] = strtolower(trim($d));
                }
                $this->saveConfig($custom);
            }
            
            $this->respond(['ok' => true, 'updated' => true]);
        }
    }
    
    public function handleStatus() {
        $this->respond([
            'ok' => true,
            'status' => 'online',
            'service' => SERVICE_NAME,
            'version' => SERVICE_VERSION,
            'ts' => time()
        ], false); // Not encrypted (health check)
    }
    
    public function handleBinary() {
        // Binary protocol for even more stealth
        $auth = $this->authenticate();
        
        $body = file_get_contents('php://input');
        if (strlen($body) < 4) {
            http_response_code(400);
            exit();
        }
        
        // Binary format: [1 byte cmd][2 bytes length][data]
        $cmd = ord($body[0]);
        $len = (ord($body[1]) << 8) | ord($body[2]);
        $data = substr($body, 3, $len);
        
        switch ($cmd) {
            case 0x01: // Query
                $domain = $data;
                $result = $this->isTarget($domain) ? 1 : 0;
                $ip = $result ? '0.0.0.0' : gethostbyname($domain);
                
                // Binary response: [1 byte result][4 bytes IP]
                $ipParts = explode('.', $ip);
                $response = chr($result);
                foreach ($ipParts as $part) {
                    $response .= chr((int)$part);
                }
                
                header('Content-Type: application/octet-stream');
                echo $response;
                exit();
                
            case 0x02: // Batch query
                $domains = explode("\n", $data);
                $response = '';
                foreach ($domains as $domain) {
                    $domain = trim($domain);
                    if (empty($domain)) continue;
                    $result = $this->isTarget($domain) ? 1 : 0;
                    $response .= chr($result);
                }
                
                header('Content-Type: application/octet-stream');
                echo $response;
                exit();
                
            case 0x03: // Get patterns (compressed)
                $patterns = implode("\n", array_map('base64_encode', $this->blocklist));
                $compressed = gzcompress($patterns, 9);
                
                header('Content-Type: application/octet-stream');
                echo $compressed;
                exit();
        }
        
        http_response_code(400);
        exit();
    }
    
    // ==================== ROUTER ====================
    
    public function route() {
        $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $uri = trim($uri, '/');
        
        // Remove base path
        $basePath = basename(__DIR__);
        $uri = preg_replace('/^' . preg_quote($basePath, '/') . '\//', '', $uri);
        $uri = preg_replace('/^Dns\.php\/?/', '', $uri);
        
        $path = strtolower(trim($uri, '/'));
        
        // Binary endpoint
        if ($path === 'bin' || $path === 'b64' || $path === 'raw') {
            $this->handleBinary();
            return;
        }
        
        // Match obfuscated endpoints
        if ($this->matchEndpoint($path, 'init') || empty($path)) {
            $this->handleInit();
        } else if ($this->matchEndpoint($path, 'query')) {
            $this->handleQuery();
        } else if ($this->matchEndpoint($path, 'check')) {
            $this->handleCheck();
        } else if ($this->matchEndpoint($path, 'batch')) {
            $this->handleBatch();
        } else if ($this->matchEndpoint($path, 'sync')) {
            $this->handleSync();
        } else if ($this->matchEndpoint($path, 'status')) {
            $this->handleStatus();
        } else {
            // Unknown endpoint - return fake 404 like normal API
            http_response_code(404);
            echo json_encode([
                'status' => 'error',
                'service' => SERVICE_NAME,
                'message' => 'Endpoint not found',
                'code' => 404
            ]);
        }
    }
}

// Run
$service = new StealthService();
$service->route();
