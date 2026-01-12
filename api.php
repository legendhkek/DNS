<?php
/**
 * API for libbgmi.so protection
 * Host this file on your server
 * 
 * Usage from C++: http://your-server.com/api.php?c=i (init)
 * Usage from C++: http://your-server.com/api.php?c=c&t=domain.com (check block)
 * Usage for .so:  http://your-server.com/api.php?connect=libbgmi.so (obfuscate)
 */

header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json');

// Ad/tracking domains to block
$_bl = ['doubleclick','googlesyndication','googleadservices','admob','adsense','adnxs','mopub','unityads','applovin','vungle','chartboost','ironsrc','inmobi','tapjoy','facebook.com/tr','pixel.facebook','analytics','tracker','tracking','telemetry','mixpanel','adjust','appsflyer','popads','taboola','crashlytics','flurry','google-analytics','googletagmanager'];

// Command
$c = $_GET['c'] ?? $_REQUEST['c'] ?? null;
$t = $_GET['t'] ?? $_REQUEST['t'] ?? '';

// Check if domain should be blocked
function shouldBlock($domain) {
    global $_bl;
    $domain = strtolower($domain);
    foreach ($_bl as $b) {
        if (strpos($domain, $b) !== false) return true;
    }
    return false;
}

// Handle commands from C++ code
if ($c !== null) {
    switch ($c) {
        case 'i': // Init
            echo json_encode(['s' => 1, 'v' => '1.0', 't' => time()]);
            break;
        case 'c': // Check domain
            echo json_encode(['s' => 1, 'f' => shouldBlock($t) ? 1 : 0]);
            break;
        case 'b': // Batch check
            $list = $_POST['l'] ?? [];
            $r = [];
            foreach ($list as $d) {
                $r[$d] = ['f' => shouldBlock($d) ? 1 : 0];
            }
            echo json_encode(['s' => 1, 'r' => $r]);
            break;
        default:
            echo json_encode(['s' => 1]);
    }
    exit;
}

// Handle .so obfuscation via ?connect=
$connect = $_GET['connect'] ?? null;

if ($connect === null) {
    echo json_encode([
        'api' => 'bgmi_protect',
        'version' => '1.0',
        'endpoints' => [
            '?c=i' => 'Initialize connection',
            '?c=c&t=domain' => 'Check if domain blocked',
            '?connect=lib.so' => 'Obfuscate library file'
        ]
    ]);
    exit;
}

// Find library file
$paths = ['./', 'libs/', 'lib/'];
$found = null;
foreach ($paths as $p) {
    if (file_exists($p . $connect)) {
        $found = $p . $connect;
        break;
    }
}
if (!$found && file_exists($connect)) $found = $connect;

if (!$found) {
    http_response_code(404);
    echo json_encode(['error' => 'File not found', 'path' => $connect]);
    exit;
}

// Obfuscation functions
function xorEncrypt($data, $key) {
    $out = '';
    $kl = strlen($key);
    for ($i = 0; $i < strlen($data); $i++) {
        $out .= $data[$i] ^ $key[$i % $kl];
    }
    return $out;
}

function rc4($data, $key) {
    $s = range(0, 255);
    $j = 0;
    for ($i = 0; $i < 256; $i++) {
        $j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
        $t = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $t;
    }
    $i = $j = 0;
    $out = '';
    for ($x = 0; $x < strlen($data); $x++) {
        $i = ($i + 1) % 256;
        $j = ($j + $s[$i]) % 256;
        $t = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $t;
        $out .= chr(ord($data[$x]) ^ $s[($s[$i] + $s[$j]) % 256]);
    }
    return $out;
}

// Read and obfuscate
$data = file_get_contents($found);
$key = hash('sha256', date('YmdH') . 'bgmi');

// Multi-layer encryption
$e1 = xorEncrypt($data, $key);
$e2 = rc4($e1, $key);

// Add header
$header = "\x00PROTECT\x00";
$meta = pack('V', strlen($data)) . pack('V', crc32($data)) . pack('V', time());
$output = $header . $meta . $e2;

// Send file
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . basename($connect) . '.protected"');
header('Content-Length: ' . strlen($output));
echo $output;
