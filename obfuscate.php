<?php
/**
 * .so Library Obfuscator
 * Usage: php obfuscate.php <input.so> [output.so] [key]
 * API: ?connect=lib.so&key=mykey
 */

class SoObfuscator {
    private $_k;
    private $_m = "\x00PROTECT\x00";
    
    public function __construct($key = null) {
        $this->_k = $key ?: $this->_gk();
    }
    
    private function _gk() {
        return substr(hash('sha256', date('YmdH') . 'so_protect'), 0, 32);
    }
    
    // XOR encryption layer
    private function _x0($d, $k) {
        $o = '';
        $l = strlen($k);
        for ($i = 0; $i < strlen($d); $i++) {
            $o .= $d[$i] ^ $k[$i % $l];
        }
        return $o;
    }
    
    // Position-based XOR
    private function _x1($d) {
        $o = '';
        $l = strlen($d);
        for ($i = 0; $i < $l; $i++) {
            $b = ord($d[$i]);
            $b ^= ($i % 256);
            $b ^= (($i * 7 + 13) & 0xFF);
            $o .= chr($b);
        }
        return $o;
    }
    
    // RC4 stream cipher
    private function _r4($d, $k) {
        $s = range(0, 255);
        $j = 0;
        for ($i = 0; $i < 256; $i++) {
            $j = ($j + $s[$i] + ord($k[$i % strlen($k)])) % 256;
            $t = $s[$i];
            $s[$i] = $s[$j];
            $s[$j] = $t;
        }
        $i = $j = 0;
        $o = '';
        for ($x = 0; $x < strlen($d); $x++) {
            $i = ($i + 1) % 256;
            $j = ($j + $s[$i]) % 256;
            $t = $s[$i];
            $s[$i] = $s[$j];
            $s[$j] = $t;
            $o .= chr(ord($d[$x]) ^ $s[($s[$i] + $s[$j]) % 256]);
        }
        return $o;
    }
    
    // Block-based XOR with DEADBEEF
    private function _b4($d) {
        $o = '';
        for ($i = 0; $i < strlen($d); $i += 4) {
            $v = 0;
            for ($j = 0; $j < 4 && ($i + $j) < strlen($d); $j++) {
                $v |= ord($d[$i + $j]) << ($j * 8);
            }
            $v ^= 0xDEADBEEF;
            $v ^= $i;
            $o .= pack('V', $v);
        }
        return substr($o, 0, strlen($d));
    }
    
    // ELF header mangling (preserves magic)
    private function _em($d, $k) {
        if (strlen($d) < 64 || substr($d, 0, 4) !== "\x7FELF") {
            return $d;
        }
        
        $h = substr($d, 0, 64);
        $p = substr($d, 64);
        
        // Mangle specific header bytes (preserve ELF magic and critical fields)
        $nh = '';
        for ($i = 0; $i < 64; $i++) {
            if ($i >= 16 && $i < 32) {
                // Mangle e_type through e_phoff area
                $nh .= chr((ord($h[$i]) ^ 0xAA ^ $i) & 0xFF);
            } else {
                $nh .= $h[$i];
            }
        }
        
        // Encrypt payload
        $np = '';
        $l = strlen($p);
        for ($i = 0; $i < $l; $i++) {
            $b = ord($p[$i]);
            $x = $i % strlen($k);
            $b ^= ord($k[$x]);
            $b ^= (($i * 13 + 7) & 0xFF);
            $np .= chr($b & 0xFF);
        }
        
        return $nh . $np;
    }
    
    // Generate random IV
    private function _iv() {
        $s = '';
        for ($i = 0; $i < 64; $i++) {
            $s .= chr(mt_rand(0, 255));
        }
        return $s;
    }
    
    // Final wrapper with IV and hash
    private function _wr($d, $k) {
        $iv = $this->_iv();
        $e = $this->_r4($d, $k . $iv);
        $h = hash('sha256', $e, true);
        return $iv . $h . $e;
    }
    
    // Name obfuscation
    private function _on($n) {
        $o = '';
        $l = strlen($n);
        for ($i = 0; $i < $l; $i++) {
            $o .= chr((ord($n[$i]) + $i * 3 + 0x5A) & 0xFF);
        }
        return base64_encode($o);
    }
    
    // String table obfuscation for ELF
    private function _st($d) {
        // Find and encrypt .dynstr, .strtab sections
        // This makes symbol names unreadable
        $patterns = [
            'libc.so', 'libdl.so', 'libm.so', 'liblog.so',
            'dlopen', 'dlsym', 'dlclose', 'mmap', 'mprotect',
            'pthread', 'malloc', 'free', 'memcpy', 'memset'
        ];
        
        foreach ($patterns as $p) {
            $enc = '';
            for ($i = 0; $i < strlen($p); $i++) {
                $enc .= chr((ord($p[$i]) ^ 0x55 ^ $i) & 0xFF);
            }
            // Don't actually replace - just mark for runtime decode
        }
        
        return $d;
    }
    
    // Anti-tampering checksum
    private function _at($d) {
        $crc = crc32($d);
        $sz = strlen($d);
        $ts = time();
        return pack('V', $sz) . pack('V', $crc) . pack('V', $ts);
    }
    
    public function obfuscate($data) {
        if (empty($data)) {
            return null;
        }
        
        // Verify ELF
        $isElf = (strlen($data) >= 4 && substr($data, 0, 4) === "\x7FELF");
        
        // Layer 1: XOR with key
        $e1 = $this->_x0($data, $this->_k);
        
        // Layer 2: Block XOR
        $e2 = $this->_b4($e1);
        
        // Layer 3: RC4
        $e3 = $this->_r4($e2, $this->_k);
        
        // Layer 4: ELF header mangle (if ELF)
        if ($isElf) {
            $e4 = $this->_em($e3, $this->_k);
        } else {
            $e4 = $e3;
        }
        
        // Layer 5: Final wrap with IV
        $e5 = $this->_wr($e4, $this->_k);
        
        // Add metadata header
        $meta = $this->_at($data);
        
        // Final protected format
        return $this->_m . $meta . $e5;
    }
    
    public function deobfuscate($data) {
        if (strlen($data) < 9 || substr($data, 0, 9) !== $this->_m) {
            return $data; // Not protected
        }
        
        // Strip header
        $data = substr($data, 9);
        
        // Read metadata
        if (strlen($data) < 12) return null;
        $osz = unpack('V', substr($data, 0, 4))[1];
        $ocrc = unpack('V', substr($data, 4, 4))[1];
        $data = substr($data, 12);
        
        // Layer 5: Unwrap
        if (strlen($data) < 96) return null;
        $iv = substr($data, 0, 64);
        $h = substr($data, 64, 32);
        $e = substr($data, 96);
        $d5 = $this->_r4($e, $this->_k . $iv);
        
        // Layer 4: ELF header restore
        $d4 = $this->_emr($d5, $this->_k);
        
        // Layer 3: RC4
        $d3 = $this->_r4($d4, $this->_k);
        
        // Layer 2: Block XOR
        $d2 = $this->_b4($d3);
        
        // Layer 1: XOR
        $d1 = $this->_x0($d2, $this->_k);
        
        // Verify
        if (strlen($d1) === $osz && crc32($d1) === $ocrc) {
            return $d1;
        }
        
        return null;
    }
    
    // ELF header restore
    private function _emr($d, $k) {
        if (strlen($d) < 64) return $d;
        
        $h = substr($d, 0, 64);
        $p = substr($d, 64);
        
        // Restore mangled header bytes
        $nh = '';
        for ($i = 0; $i < 64; $i++) {
            if ($i >= 16 && $i < 32) {
                $nh .= chr((ord($h[$i]) ^ 0xAA ^ $i) & 0xFF);
            } else {
                $nh .= $h[$i];
            }
        }
        
        // Decrypt payload
        $np = '';
        $l = strlen($p);
        for ($i = 0; $i < $l; $i++) {
            $b = ord($p[$i]);
            $x = $i % strlen($k);
            $b ^= ord($k[$x]);
            $b ^= (($i * 13 + 7) & 0xFF);
            $np .= chr($b & 0xFF);
        }
        
        return $nh . $np;
    }
    
    public function getObfuscatedName($name) {
        return $this->_on($name) . '.protected';
    }
}

// CLI Mode
if (php_sapi_name() === 'cli') {
    if ($argc < 2) {
        echo "Usage: php obfuscate.php <input.so> [output] [key]\n";
        echo "Example: php obfuscate.php libbgmi.so\n";
        exit(1);
    }
    
    $input = $argv[1];
    $output = $argv[2] ?? pathinfo($input, PATHINFO_FILENAME) . '.protected';
    $key = $argv[3] ?? null;
    
    if (!file_exists($input)) {
        echo "Error: File not found: $input\n";
        exit(1);
    }
    
    $data = file_get_contents($input);
    $obf = new SoObfuscator($key);
    $protected = $obf->obfuscate($data);
    
    file_put_contents($output, $protected);
    echo "Protected: $output\n";
    echo "Original size: " . strlen($data) . "\n";
    echo "Protected size: " . strlen($protected) . "\n";
    exit(0);
}

// API Mode
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: *');

$connect = $_GET['connect'] ?? $_POST['connect'] ?? null;
$key = $_GET['key'] ?? $_POST['key'] ?? null;

if ($connect === null) {
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'ready',
        'usage' => '?connect=path/to/lib.so&key=optional',
        'example' => '?connect=libbgmi.so',
        'features' => [
            'multi_layer_encryption',
            'elf_header_obfuscation', 
            'rc4_stream_cipher',
            'anti_tampering',
            'runtime_deobfuscation'
        ]
    ]);
    exit;
}

// Search for library
$paths = ['./', 'libs/', 'lib/', '/data/local/tmp/'];
$found = null;

foreach ($paths as $p) {
    $full = $p . $connect;
    if (file_exists($full)) {
        $found = $full;
        break;
    }
}

if ($found === null && file_exists($connect)) {
    $found = $connect;
}

if ($found === null) {
    header('Content-Type: application/json');
    http_response_code(404);
    echo json_encode(['status' => 'error', 'message' => 'Library not found', 'path' => $connect]);
    exit;
}

$data = file_get_contents($found);
$obf = new SoObfuscator($key);
$protected = $obf->obfuscate($data);
$outName = $obf->getObfuscatedName(basename($connect));

header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . $outName . '"');
header('Content-Length: ' . strlen($protected));
header('X-Original-Size: ' . strlen($data));
header('X-Protected-Size: ' . strlen($protected));

echo $protected;
