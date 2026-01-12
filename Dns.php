<?php
/**
 * Game Config Sync API
 * Looks like normal game configuration/data sync endpoint
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Game-ID, X-Session');
header('Server: nginx');
header('X-Powered-By: GameServer/2.1');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit();
}

// Blocked patterns (base64 encoded for obfuscation)
$p = [
    'ZG91YmxlY2xpY2s=','Z29vZ2xlc3luZGljYXRpb24=','Z29vZ2xlYWRzZXJ2aWNlcw==',
    'Z29vZ2xlLWFuYWx5dGljcw==','Z29vZ2xldGFnbWFuYWdlcg==','YWRzZXJ2aWNl',
    'cGFnZWFk','YWRtb2I=','YWRzZW5zZQ==','YWRueHM=','YWR2ZXJ0aXNpbmc=',
    'bW9wdWI=','dW5pdHlhZHM=','YXBwbG92aW4=','dnVuZ2xl','Y2hhcnRib29zdA==',
    'aXJvbnNyYw==','aW5tb2Jp','dGFwam95','ZnliZXI=','YW4uZmFjZWJvb2s=',
    'cGl4ZWwuZmFjZWJvb2s=','YW5hbHl0aWNz','dHJhY2tlcg==','dHJhY2tpbmc=',
    'dGVsZW1ldHJ5','bWl4cGFuZWw=','c2VnbWVudA==','YW1wbGl0dWRl',
    'YnJhbmNoLmlv','YWRqdXN0','YXBwc2ZseWVy','a29jaGF2YQ==',
    'cG9wYWRz','cG9wY2FzaA==','dGFib29sYQ==','b3V0YnJhaW4=',
    'Y3Jhc2hseXRpY3M=','Zmx1cnJ5','c2NvcmVjYXJk','cXVhbnRzZXJ2ZQ=='
];

$patterns = array_map('base64_decode', $p);

function check($d, $patterns) {
    $d = strtolower(trim($d));
    foreach ($patterns as $pt) {
        if (strpos($d, $pt) !== false) return true;
    }
    return false;
}

function respond($data) {
    echo json_encode($data);
    exit();
}

// Get request path
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path = strtolower(trim(preg_replace('/^.*Dns\.php\/?/', '', $uri), '/'));

// Get input
$d = $_REQUEST['d'] ?? $_REQUEST['q'] ?? $_REQUEST['h'] ?? null;

if (!$d && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $body = file_get_contents('php://input');
    $json = json_decode($body, true);
    $d = $json['d'] ?? $json['q'] ?? $json['h'] ?? $json['list'] ?? null;
}

switch ($path) {
    case '':
    case 'c':
    case 'connect':
    case 'sync':
    case 'init':
        // Connect/Init - always success
        respond([
            'ok' => true,
            'ts' => time(),
            'v' => '2.1',
            'n' => count($patterns)
        ]);
        break;
        
    case 'q':
    case 'query':
    case 'get':
    case 'r':
        // Query single domain
        if (!$d) respond(['ok' => false, 'e' => 1]);
        
        $blocked = check($d, $patterns);
        if ($blocked) {
            respond(['ok' => true, 'd' => $d, 'r' => 1, 'ip' => '0.0.0.0']);
        } else {
            $ip = gethostbyname($d);
            respond(['ok' => true, 'd' => $d, 'r' => 0, 'ip' => ($ip !== $d) ? $ip : null]);
        }
        break;
        
    case 'k':
    case 'check':
    case 'v':
        // Quick check
        if (!$d) respond(['ok' => false, 'e' => 1]);
        respond(['ok' => true, 'r' => check($d, $patterns) ? 1 : 0]);
        break;
        
    case 'b':
    case 'batch':
    case 'm':
        // Batch query
        $list = is_array($d) ? $d : [];
        if (empty($list)) respond(['ok' => false, 'e' => 1]);
        
        $res = [];
        foreach (array_slice($list, 0, 50) as $item) {
            $item = strtolower(trim($item));
            $blocked = check($item, $patterns);
            $res[$item] = ['r' => $blocked ? 1 : 0];
            if (!$blocked) {
                $ip = gethostbyname($item);
                $res[$item]['ip'] = ($ip !== $item) ? $ip : null;
            }
        }
        respond(['ok' => true, 'res' => $res]);
        break;
        
    case 'l':
    case 'list':
    case 'data':
        // Get patterns (encoded)
        respond(['ok' => true, 'data' => $p]);
        break;
        
    case 'p':
    case 'ping':
    case 'health':
        // Health check
        respond(['ok' => true, 'ts' => time()]);
        break;
        
    default:
        respond(['ok' => true, 'ts' => time()]);
}
