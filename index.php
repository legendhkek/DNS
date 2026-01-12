<?php
/**
 * .so Library Protection API
 * 
 * Endpoints:
 *   GET  /                     - API info
 *   GET  /?connect=lib.so      - Obfuscate and download library
 *   POST /upload               - Upload and obfuscate library
 */

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: *');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Include obfuscator
require_once __DIR__ . '/obfuscate.php';

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$connect = $_GET['connect'] ?? null;

// API Info
if ($connect === null && $uri === '/' && $_SERVER['REQUEST_METHOD'] === 'GET' && empty($_FILES)) {
    header('Content-Type: application/json');
    echo json_encode([
        'name' => 'SO Protection API',
        'version' => '1.0.0',
        'endpoints' => [
            'GET /?connect=<library>' => 'Obfuscate library from server path',
            'GET /?connect=<library>&key=<key>' => 'Obfuscate with custom key',
            'POST /upload (file=<.so file>)' => 'Upload and obfuscate library'
        ],
        'example' => [
            'url' => '/?connect=libbgmi.so',
            'description' => 'Downloads obfuscated libbgmi.so'
        ],
        'protection_layers' => [
            '1. XOR encryption with time-based key',
            '2. Block-level XOR transformation', 
            '3. RC4 stream cipher',
            '4. ELF header obfuscation',
            '5. IV-wrapped final encryption',
            '6. Anti-tampering checksum'
        ],
        'client_loader' => 'See /examples/cpp/SoLoader.h for C++ runtime loader'
    ], JSON_PRETTY_PRINT);
    exit;
}

// Handle file upload
if (!empty($_FILES['file'])) {
    $file = $_FILES['file'];
    
    if ($file['error'] !== UPLOAD_ERR_OK) {
        header('Content-Type: application/json');
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Upload failed']);
        exit;
    }
    
    $data = file_get_contents($file['tmp_name']);
    $key = $_POST['key'] ?? null;
    
    $obf = new SoObfuscator($key);
    $protected = $obf->obfuscate($data);
    $outName = $obf->getObfuscatedName($file['name']);
    
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $outName . '"');
    header('Content-Length: ' . strlen($protected));
    
    echo $protected;
    exit;
}

// Handle connect parameter - redirect to obfuscate.php
if ($connect !== null) {
    include __DIR__ . '/obfuscate.php';
    exit;
}

// Default - show simple HTML form
?>
<!DOCTYPE html>
<html>
<head>
    <title>SO Protection API</title>
    <style>
        body { font-family: monospace; background: #1a1a2e; color: #eee; padding: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { color: #00ff88; }
        .endpoint { background: #16213e; padding: 15px; margin: 10px 0; border-radius: 5px; }
        code { background: #0f3460; padding: 2px 8px; border-radius: 3px; color: #00ff88; }
        input, button { padding: 10px; margin: 5px 0; border: none; border-radius: 5px; }
        input[type="text"] { width: 300px; background: #16213e; color: #fff; }
        input[type="file"] { background: #16213e; color: #fff; }
        button { background: #00ff88; color: #000; cursor: pointer; font-weight: bold; }
        button:hover { background: #00cc6a; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SO Protection API</h1>
        
        <div class="endpoint">
            <h3>Method 1: URL Parameter</h3>
            <form method="GET" action="/">
                <input type="text" name="connect" placeholder="libbgmi.so" required>
                <input type="text" name="key" placeholder="optional key">
                <button type="submit">Obfuscate</button>
            </form>
            <p>Example: <code>/?connect=libbgmi.so</code></p>
        </div>
        
        <div class="endpoint">
            <h3>Method 2: File Upload</h3>
            <form method="POST" enctype="multipart/form-data">
                <input type="file" name="file" accept=".so,.dll" required><br>
                <input type="text" name="key" placeholder="optional key">
                <button type="submit">Upload & Obfuscate</button>
            </form>
        </div>
        
        <div class="endpoint">
            <h3>Protection Features</h3>
            <ul>
                <li>Multi-layer XOR encryption</li>
                <li>RC4 stream cipher</li>
                <li>ELF header obfuscation</li>
                <li>Anti-tampering checksums</li>
                <li>Time-based key rotation</li>
            </ul>
        </div>
    </div>
</body>
</html>
