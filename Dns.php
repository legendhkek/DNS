<?php
// Tencent Game Services - Config Sync
header('Server: TencentCloud/1.0');
header('Content-Type: application/json; charset=utf-8');
header('X-TC-Action: SyncGameConfig');
header('X-TC-Version: 2023-01-01');
header('X-TC-Region: ap-mumbai');
header('X-TC-RequestId: ' . strtoupper(bin2hex(random_bytes(16))));
header('X-TC-Timestamp: ' . time());
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: *');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// Key rotation
$h = date('YmdH');
$k = substr(hash('sha256', $h . 'tc'), 0, 32);

// XOR
function x($d, $k) { $o=''; $l=strlen($k); for($i=0;$i<strlen($d);$i++) $o.=$d[$i]^$k[$i%$l]; return $o; }

// Encode
function e($d, $k) { return base64_encode(x(json_encode($d), $k)); }

// Decode
function d($d, $k) { $x = @base64_decode($d); return $x ? json_decode(x($x, $k), true) : null; }

// Patterns
$_p = ['ZG91YmxlY2xpY2s','Z29vZ2xlc3luZGljYXRpb24','Z29vZ2xlYWRzZXJ2aWNlcw','YWRtb2I','YWRzZW5zZQ',
'YWRueHM','bW9wdWI','dW5pdHlhZHM','YXBwbG92aW4','dnVuZ2xl','Y2hhcnRib29zdA','aXJvbnNyYw','aW5tb2Jp',
'dGFwam95','YW4uZmFjZWJvb2s','cGl4ZWwuZmFjZWJvb2s','YW5hbHl0aWNz','dHJhY2tlcg','dHJhY2tpbmc',
'dGVsZW1ldHJ5','bWl4cGFuZWw','YWRqdXN0','YXBwc2ZseWVy','cG9wYWRz','dGFib29sYQ','Y3Jhc2hseXRpY3M',
'Zmx1cnJ5','Z29vZ2xlLWFuYWx5dGljcw','Z29vZ2xldGFnbWFuYWdlcg','YWRzZXJ2aWNl','cGFnZWFk','YWR2ZXJ0aXNpbmc'];
$pt = array_map('base64_decode', $_p);

function chk($d) { global $pt; $d=strtolower($d); foreach($pt as $p) if(strpos($d,$p)!==false) return 1; return 0; }

// Input
$in = null;
$body = file_get_contents('php://input');
if ($body) $in = d($body, $k);
if (!$in && isset($_GET['d'])) $in = d($_GET['d'], $k);
if (!$in) $in = ['c' => $_GET['c'] ?? 'i', 't' => $_GET['t'] ?? ''];

$c = $in['c'] ?? 'i';
$t = $in['t'] ?? '';

// Response wrapper (looks like BGMI config)
function resp($data, $k) {
    global $h;
    $enc = e($data, $k);
    return json_encode([
        'Response' => [
            'RequestId' => strtoupper(bin2hex(random_bytes(16))),
            'GameConfig' => [
                'Version' => '2.8.0',
                'Region' => 'INDIA',
                'Season' => 'S' . (intval(date('m')) + 20),
                'ConfigData' => $enc,
                'Timestamp' => time(),
                'Hash' => substr(md5($enc), 0, 16)
            ],
            'PlayerData' => [
                'Tier' => ['Rank' => rand(1,6), 'Points' => rand(1000,5000)],
                'Stats' => ['Matches' => rand(100,999), 'Wins' => rand(10,99)],
                'Inventory' => ['UC' => rand(100,9999), 'BP' => rand(10000,99999)]
            ]
        ]
    ]);
}

switch ($c) {
    case 'i': // Init
        $r = ['s'=>1, 'k'=>$k, 'h'=>$h, 'n'=>count($pt)];
        break;
    case 'q': // Query
        $f = chk($t);
        $r = ['s'=>1, 't'=>$t, 'f'=>$f, 'v'=>$f?'0.0.0.0':@gethostbyname($t)];
        break;
    case 'c': // Check
        $r = ['s'=>1, 'f'=>chk($t)];
        break;
    case 'b': // Batch
        $l = $in['l'] ?? [];
        $res = [];
        foreach(array_slice($l,0,50) as $d) $res[$d] = ['f'=>chk($d)];
        $r = ['s'=>1, 'r'=>$res];
        break;
    default:
        $r = ['s'=>1];
}

echo resp($r, $k);
