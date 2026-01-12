<?php
$_=base64_decode;$__='aGVhZGVy';$___='Q29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0=';$____='Q2FjaGUtQ29udHJvbDogbm8tY2FjaGUsIG5vLXN0b3Jl';$_____='WC1Db250ZW50LVR5cGUtT3B0aW9uczogbm9zbmlmZg==';$______='QWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luOiAq';
$_($__)(($_($$___)));$_($__)(($_($$____)));$_($__)(($_($$_____)));$_($__)(($_($$______)));

// Library path from connect parameter
$_a0=isset($_GET['connect'])?$_GET['connect']:null;
$_a1=isset($_GET['key'])?$_GET['key']:'';
$_a2=date('YmdH');
$_a3=substr(hash('sha256',$_a2.'so_protect'),0,32);

function _b0($_d,$_k){$_o='';$_l=strlen($_k);for($_i=0;$_i<strlen($_d);$_i++)$_o.=$_d[$_i]^$_k[$_i%$_l];return $_o;}
function _b1($_d){$_t=[];$_l=strlen($_d);for($_i=0;$_i<$_l;$_i++){$_b=$_i%256;$_t[$_i]=ord($_d[$_i])^$_b^(($_i*7+13)&0xFF);}return implode('',array_map('chr',$_t));}
function _b2($_d){$_h=substr(hash('sha512',$_d,true),0,32);return $_h._b1($_d);}
function _b3($_d,$_k){$_s=range(0,255);$_j=0;for($_i=0;$_i<256;$_i++){$_j=($_j+$_s[$_i]+ord($_k[$_i%strlen($_k)]))%256;$_t=$_s[$_i];$_s[$_i]=$_s[$_j];$_s[$_j]=$_t;}$_i=$_j=0;$_o='';for($_x=0;$_x<strlen($_d);$_x++){$_i=($_i+1)%256;$_j=($_j+$_s[$_i])%256;$_t=$_s[$_i];$_s[$_i]=$_s[$_j];$_s[$_j]=$_t;$_o.=chr(ord($_d[$_x])^$_s[($_s[$_i]+$_s[$_j])%256]);}return $_o;}
function _b4($_d){$_c=[];for($_i=0;$_i<strlen($_d);$_i+=4){$_v=0;for($_j=0;$_j<4&&$_i+$_j<strlen($_d);$_j++)$_v|=ord($_d[$_i+$_j])<<($_j*8);$_c[]=pack('V',$_v^0xDEADBEEF^$_i);}return implode('',$_c);}
function _b5($_n){$_p=['lib','bgmi','.so','game','hack','mod','cheat','inject','hook','patch'];$_o='';$_l=strlen($_n);for($_i=0;$_i<$_l;$_i++)$_o.=chr((ord($_n[$_i])+$_i*3+0x5A)&0xFF);return base64_encode($_o);}
function _b6($_d,$_m){$_e7="\x7F\x45\x4C\x46";if(substr($_d,0,4)!==$_e7)return null;$_h=substr($_d,0,64);$_p=substr($_d,64);$_nh='';for($_i=0;$_i<64;$_i++){if($_i>=16&&$_i<32){$_nh.=chr((ord($_h[$_i])^0xAA^$_i)&0xFF);}else{$_nh.=$_h[$_i];}}$_np='';$_l=strlen($_p);for($_i=0;$_i<$_l;$_i++){$_b=ord($_p[$_i]);$_x=$_i%strlen($_m);$_b^=ord($_m[$_x]);$_b^=(($_i*13+7)&0xFF);$_np.=chr($_b&0xFF);}return $_nh.$_np;}
function _b7(){$_s=[];for($_i=0;$_i<64;$_i++)$_s[]=mt_rand(0,255);return implode('',array_map('chr',$_s));}
function _b8($_d,$_k){$_iv=_b7();$_e=_b3($_d,$_k.$_iv);$_h=hash('sha256',$_e,true);return $_iv.$_h.$_e;}

if($_a0===null){
    header('Content-Type: application/json');
    echo json_encode(['status'=>'error','message'=>'Usage: ?connect=path/to/lib.so&key=optional_key','example'=>'?connect=libbgmi.so','supported'=>['.so','.dll'],'obfuscation'=>['xor_layered','rc4_stream','elf_header_mangle','symbol_strip','section_encrypt']]);
    exit;
}

$_c0=realpath($_a0);
if($_c0===false||!file_exists($_c0)){
    $__p=['libs','lib','./'];
    foreach($__p as $_d){
        $_t=$_d.'/'.$_a0;
        if(file_exists($_t)){$_c0=$_t;break;}
    }
}

if(!$_c0||!file_exists($_c0)){
    header('Content-Type: application/json');
    http_response_code(404);
    echo json_encode(['status'=>'error','message'=>'Library not found','path'=>$_a0]);
    exit;
}

$_d0=file_get_contents($_c0);
if($_d0===false){
    header('Content-Type: application/json');
    http_response_code(500);
    echo json_encode(['status'=>'error','message'=>'Failed to read library']);
    exit;
}

$_k0=empty($_a1)?$_a3:hash('sha256',$_a1.$_a3);
$_e0=_b0($_d0,$_k0);
$_e1=_b4($_e0);
$_e2=_b3($_e1,$_k0);
$_e3=_b6($_e2,$_k0);
if($_e3===null)$_e3=$_e2;
$_f0=_b8($_e3,$_k0);
$_n0=_b5(basename($_a0));
$_m0=pack('V',strlen($_d0)).pack('V',crc32($_d0)).pack('V',time());
$_o0="\x00\x50\x52\x4F\x54\x45\x43\x54\x00".$_m0.$_f0;

header('Content-Disposition: attachment; filename="'.$_n0.'.protected"');
header('Content-Length: '.strlen($_o0));
header('X-Original-Size: '.strlen($_d0));
header('X-Protected-Size: '.strlen($_o0));
header('X-Protection-Key: '.substr($_k0,0,8).'...');
echo $_o0;
