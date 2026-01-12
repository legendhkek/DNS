<?php
/**
 * Game Data Sync Service
 * Looks like normal game server communication
 */

// Random server headers (looks like game server)
$servers = ['GameServer/2.1', 'Unity/2021.3', 'PlayFab/1.0', 'CloudScript/3.2'];
header('Server: ' . $servers[array_rand($servers)]);
header('Content-Type: application/octet-stream');
header('X-Unity-Version: 2021.3.15f1');
header('X-Request-Id: ' . bin2hex(random_bytes(8)));
header('Cache-Control: no-store');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST');
header('Access-Control-Allow-Headers: *');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// Encryption key (changes based on time - rotates every hour)
$tk = base64_encode(hash('sha256', date('YmdH') . 'gx', true));

// XOR encrypt/decrypt
function xe($d, $k) {
    $o = ''; $kl = strlen($k);
    for ($i = 0; $i < strlen($d); $i++) $o .= $d[$i] ^ $k[$i % $kl];
    return $o;
}

// Encode response (encrypted + base64 + shuffled)
function enc($data, $k) {
    $j = json_encode($data);
    $x = xe($j, $k);
    $b = base64_encode($x);
    // Add random padding to change length
    $pad = bin2hex(random_bytes(rand(4, 16)));
    return $pad . '.' . $b . '.' . substr(md5($b), 0, 8);
}

// Decode request
function dec($data, $k) {
    $parts = explode('.', $data);
    if (count($parts) < 2) return null;
    $b = base64_decode($parts[1]);
    if (!$b) return null;
    $j = xe($b, $k);
    return json_decode($j, true);
}

// Obfuscated blocked patterns (double encoded)
$ep = 'eyJwIjpbIlpHOTFZbXhsWTJ4cFkyc3ciLCJaMjl2WjJ4bGMzbHVaR2xqWVhScGIyND0iLCJaMjl2WjJ4bFlXUnpaWEoyYVdObGN3PT0iLCJaMjl2WjJ4bExXRnVZV3g1ZEdsamN3PT0iLCJaMjl2WjJ4bGRHRm5iV0Z1WVdkbGNnPT0iLCJZV1J6WlhKMmFXTmwiLCJjR0ZuWldGayIsIllXUnRiMkk9IiwiWVdSelpXNXpaUT09IiwiWVdSdWVITT0iLCJZV1IyWlhKMGFYTnBibWM9IiwiYlc5d2RXST0iLCJkVzVwZEhsaFpITT0iLCJZWEJ3Ykc5MmFXND0iLCJkblZ1WjJ4bCIsIlkyaGhjblJpYjI5emRBPT0iLCJhWEp2Ym5OeVl3PT0iLCJhVzV0YjJKcCIsImRHRndhbTk1IiwiWm5saVpYST0iLCJZVzR1Wm1GalpXSnZiMnM9IiwiY0dsNFpXd3VabUZqWldKdmIycz0iLCJZVzVoYkhsMGFXTnoiLCJkSEpoWTJ0bGNnPT0iLCJkSEpoWTJ0cGJtYz0iLCJkR1ZzWlcxbGRISjUiLCJiV2w0Y0dGdVpXdz0iLCJjMlZuYldWdWRBPT0iLCJZVzF3YkdsMGRXUmwiLCJZbkpoYm1Ob0xtbHYiLCJZV1JxZFhOMCIsIllYQndjMlpzZVdWeSIsImEyOWphR0YyWVE9PSIsImNHOXdZV1J6IiwiY0c5d1kyRnphQT09IiwidEdGaWIyOXNZUT09Iiwid5kzSmhjMmhzZVhScFkzTT0iLCJabXgxY25KNSIsImMyTnZjbVZqWVhKa2NtVnpaV0Z5WTJnPSJdfQ==';
$pd = json_decode(base64_decode($ep), true);
$patterns = array_map(function($p) { return base64_decode($p); }, $pd['p'] ?? []);

// Check function
function chk($d, $patterns) {
    $d = strtolower(trim($d));
    foreach ($patterns as $p) if (strpos($d, $p) !== false) return true;
    return false;
}

// Get encrypted input
function getInput($k) {
    // Try encrypted body first
    $body = file_get_contents('php://input');
    if ($body && strpos($body, '.') !== false) {
        $dec = dec($body, $k);
        if ($dec) return $dec;
    }
    // Try query params (encrypted)
    if (isset($_GET['x'])) {
        $dec = dec($_GET['x'], $k);
        if ($dec) return $dec;
    }
    // Fallback to plain (for testing)
    $d = $_REQUEST['d'] ?? $_REQUEST['q'] ?? null;
    if ($d) return ['a' => 'q', 'd' => $d];
    return ['a' => 'i'];
}

// Generate fake game data response wrapper
function gameResponse($realData, $k) {
    $encrypted = enc($realData, $k);
    
    // Wrap in fake game data structure
    $fake = [
        'v' => '2.1.0',
        'ts' => time(),
        'sid' => bin2hex(random_bytes(16)),
        'data' => [
            'inventory' => [],
            'stats' => ['xp' => rand(1000, 9999), 'level' => rand(1, 100)],
            'config' => $encrypted,  // Real data hidden here
            'achievements' => [],
            'daily' => ['streak' => rand(1, 30), 'claimed' => (bool)rand(0, 1)]
        ],
        'checksum' => substr(md5($encrypted . time()), 0, 16)
    ];
    
    return json_encode($fake);
}

// Binary response (even more stealth)
function binaryResponse($data, $k) {
    $enc = enc($data, $k);
    $bin = pack('N', strlen($enc)) . $enc . random_bytes(rand(8, 32));
    return $bin;
}

// Process request
$input = getInput($tk);
$action = $input['a'] ?? $input['action'] ?? 'i';

switch ($action) {
    case 'i': // Init
    case 'init':
    case 'c': // Connect
        $resp = [
            's' => 1,  // success
            't' => time(),
            'k' => $tk, // current key
            'n' => count($patterns),
            'iv' => base64_encode(random_bytes(16))
        ];
        break;
        
    case 'q': // Query
    case 'query':
    case 'r': // Resolve
        $d = $input['d'] ?? $input['domain'] ?? '';
        $blocked = chk($d, $patterns);
        $resp = [
            's' => 1,
            'd' => $d,
            'f' => $blocked ? 1 : 0,  // flag: 1=blocked
            'v' => $blocked ? '0.0.0.0' : (($ip = @gethostbyname($d)) !== $d ? $ip : null)
        ];
        break;
        
    case 'k': // Check
    case 'check':
    case 'v': // Verify
        $d = $input['d'] ?? '';
        $resp = ['s' => 1, 'f' => chk($d, $patterns) ? 1 : 0];
        break;
        
    case 'b': // Batch
    case 'batch':
    case 'm': // Multi
        $list = $input['l'] ?? $input['list'] ?? $input['d'] ?? [];
        if (!is_array($list)) $list = [$list];
        $res = [];
        foreach (array_slice($list, 0, 50) as $d) {
            $d = strtolower(trim($d));
            $blocked = chk($d, $patterns);
            $res[$d] = ['f' => $blocked ? 1 : 0];
        }
        $resp = ['s' => 1, 'r' => $res];
        break;
        
    case 'p': // Patterns (encrypted)
    case 'sync':
        // Double encrypt patterns for extra security
        $encPatterns = array_map(function($p) use ($tk) {
            return base64_encode(xe($p, $tk));
        }, $patterns);
        $resp = ['s' => 1, 'p' => $encPatterns];
        break;
        
    default:
        $resp = ['s' => 1, 't' => time()];
}

// Output based on Accept header or random
$accept = $_SERVER['HTTP_ACCEPT'] ?? '';
$useBinary = (strpos($accept, 'octet-stream') !== false) || (rand(0, 10) > 7);

if ($useBinary && $action !== 'i') {
    header('Content-Type: application/octet-stream');
    echo binaryResponse($resp, $tk);
} else {
    header('Content-Type: application/json');
    echo gameResponse($resp, $tk);
}
