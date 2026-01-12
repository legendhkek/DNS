<?php
// UE4 Backend Services
header('Server: UE4-Backend/4.27');
header('Content-Type: application/json');
header('X-UE4-Version: 4.27.2');
header('X-Epic-Correlation-Id: ' . strtoupper(sprintf('%08x-%04x-%04x-%04x-%012x', mt_rand(), mt_rand(0,0xffff), mt_rand(0,0xffff), mt_rand(0,0xffff), mt_rand())));
header('X-Epic-Device-Id: ' . strtoupper(md5($_SERVER['REMOTE_ADDR'] ?? 'device')));
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: *');

if ($_SERVER['REQUEST_METHOD']==='OPTIONS'){http_response_code(204);exit;}

$h=date('YmdH');
$k=substr(hash('sha256',$h.'ue4'),0,32);

function x($d,$k){$o='';$l=strlen($k);for($i=0;$i<strlen($d);$i++)$o.=$d[$i]^$k[$i%$l];return $o;}
function e($d,$k){return base64_encode(x(json_encode($d),$k));}
function d($d,$k){$x=@base64_decode($d);return $x?json_decode(x($x,$k),true):null;}

$_p=['ZG91YmxlY2xpY2s','Z29vZ2xlc3luZGljYXRpb24','Z29vZ2xlYWRzZXJ2aWNlcw','YWRtb2I','YWRzZW5zZQ','YWRueHM','bW9wdWI','dW5pdHlhZHM','YXBwbG92aW4','dnVuZ2xl','Y2hhcnRib29zdA','aXJvbnNyYw','aW5tb2Jp','dGFwam95','YW4uZmFjZWJvb2s','cGl4ZWwuZmFjZWJvb2s','YW5hbHl0aWNz','dHJhY2tlcg','dHJhY2tpbmc','dGVsZW1ldHJ5','bWl4cGFuZWw','YWRqdXN0','YXBwc2ZseWVy','cG9wYWRz','dGFib29sYQ','Y3Jhc2hseXRpY3M','Zmx1cnJ5','Z29vZ2xlLWFuYWx5dGljcw','Z29vZ2xldGFnbWFuYWdlcg','YWRzZXJ2aWNl','cGFnZWFk','YWR2ZXJ0aXNpbmc'];
$pt=array_map('base64_decode',$_p);

function chk($d){global $pt;$d=strtolower($d);foreach($pt as $p)if(strpos($d,$p)!==false)return 1;return 0;}

$in=null;
$body=file_get_contents('php://input');
if($body)$in=d($body,$k);
if(!$in&&isset($_GET['d']))$in=d($_GET['d'],$k);
if(!$in)$in=['c'=>$_GET['c']??'i','t'=>$_GET['t']??''];

$c=$in['c']??'i';
$t=$in['t']??'';

function resp($data,$k){
    $enc=e($data,$k);
    return json_encode([
        'bSuccess'=>true,
        'Version'=>'4.27.2',
        'Timestamp'=>time(),
        'CorrelationId'=>strtoupper(sprintf('%08x-%04x-%04x-%04x-%012x',mt_rand(),mt_rand(0,0xffff),mt_rand(0,0xffff),mt_rand(0,0xffff),mt_rand())),
        'Response'=>[
            'FNetworkConfig'=>[
                'ConfigVersion'=>rand(100,999),
                'ConfigData'=>$enc,
                'Checksum'=>substr(md5($enc),0,16),
                'bIsValid'=>true
            ],
            'FPlayerState'=>[
                'PlayerId'=>rand(10000000,99999999),
                'SessionId'=>strtoupper(bin2hex(random_bytes(16))),
                'MatchId'=>strtoupper(bin2hex(random_bytes(8))),
                'TeamId'=>rand(1,4),
                'bIsAlive'=>(bool)rand(0,1)
            ],
            'FGameState'=>[
                'CurrentPlayers'=>rand(80,100),
                'SafeZonePhase'=>rand(1,8),
                'MatchTime'=>rand(100,1800),
                'ServerTick'=>rand(100000,999999)
            ]
        ]
    ]);
}

switch($c){
    case'i':$r=['s'=>1,'k'=>$k,'h'=>$h,'n'=>count($pt)];break;
    case'q':$f=chk($t);$r=['s'=>1,'t'=>$t,'f'=>$f,'v'=>$f?'0.0.0.0':@gethostbyname($t)];break;
    case'c':$r=['s'=>1,'f'=>chk($t)];break;
    case'b':$l=$in['l']??[];$res=[];foreach(array_slice($l,0,50)as$d)$res[$d]=['f'=>chk($d)];$r=['s'=>1,'r'=>$res];break;
    default:$r=['s'=>1];
}

echo resp($r,$k);
