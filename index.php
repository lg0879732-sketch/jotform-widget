<?php
// clearout.php
// Unified PHP endpoint to proxy Clearout Email Finder and Email Verify
// Serves both API endpoints and renders widget UI for Jotform iFrame integration

// Allow CORS for Jotform widget origins
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowedOrigins = [
	'https://form.jotform.com',
	'https://www.jotform.com',
	'https://widgets.jotform.io',
	'https://*.jotform.com',
];
if (in_array($origin, $allowedOrigins, true) || preg_match('/\.jotform\.com$/', $origin)) {
	header('Access-Control-Allow-Origin: ' . $origin);
	header('Vary: Origin');
}
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Methods: POST, OPTIONS');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
	http_response_code(204);
	exit;
}

// Better diagnostics during hosting/debug
@ini_set('display_errors', '1');
error_reporting(E_ALL);

// If GET with widget params, render the widget UI for Jotform iFrame
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && (isset($_GET['token']) || isset($_GET['mode']))) {
	render_widget_ui();
	exit;
}

// For non-UI requests, serve JSON (and provide a simple health check)
header('Content-Type: application/json');
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
	echo json_encode(['ok' => true, 'message' => 'Clearout endpoint up']);
	exit;
}

// Parse request body (JSON first, fallback to form-encoded)
$rawBody = file_get_contents('php://input');
$input = json_decode($rawBody, true);
if (!is_array($input)) {
	if (!empty($_POST)) {
		$input = $_POST;
	} else {
		parse_str($rawBody, $asForm);
		if (is_array($asForm) && !empty($asForm)) {
			$input = $asForm;
		} else {
			http_response_code(400);
			echo json_encode(['ok' => false, 'error' => 'Invalid request body']);
			exit;
		}
	}
}

$action = strtolower(trim($input['action'] ?? 'verify')); // 'find' | 'verify' | 'both'
$token  = trim($input['token'] ?? '');                     // Clearout token (key:secret)
// Fallbacks: accept token via query (?token=) or Authorization: Bearer <token>
if ($token === '' && isset($_GET['token'])) {
	$token = trim((string)$_GET['token']);
}
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['HTTP_AUTHENTICATION'] ?? '';
if ($token === '' && preg_match('/Bearer\s+(.+)/i', $authHeader, $m)) {
	$token = trim($m[1]);
}
$email  = trim($input['email'] ?? '');
$first  = trim($input['first_name'] ?? '');
$last   = trim($input['last_name'] ?? '');
$name   = trim($input['name'] ?? '');
$domain = trim($input['domain'] ?? '');
if ($name === '' && ($first !== '' || $last !== '')) {
	$name = trim($first . ' ' . $last);
}

if ($token === '') {
	http_response_code(400);
	echo json_encode(['ok' => false, 'error' => 'Missing Clearout token']);
	exit;
}

/**
 * Call Clearout API with standard options.
 */
function call_clearout(string $url, array $payload, string $token, int $timeoutMs = 90000): array
{
	$payload['timeout'] = $payload['timeout'] ?? $timeoutMs; // default timeout
	$ch = curl_init($url);
	curl_setopt_array($ch, [
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_POST           => true,
		CURLOPT_POSTFIELDS     => json_encode($payload),
		CURLOPT_HTTPHEADER     => [
			'Content-Type: application/json',
			'Authorization: Bearer ' . $token,
		],
		CURLOPT_TIMEOUT        => max(1, (int)ceil(($payload['timeout']) / 1000)),
		CURLOPT_SSL_VERIFYPEER => true,
		CURLOPT_USERAGENT      => 'Clearout-Jotform-Widget/1.0',
	]);
	$response = curl_exec($ch);
	$error    = curl_error($ch);
	$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
	curl_close($ch);
	if ($error) {
		return ['status' => 'error', 'message' => $error];
	}
	if ($httpCode >= 400) {
		return ['status' => 'error', 'message' => 'HTTP ' . $httpCode, 'http_code' => $httpCode];
	}
	$decoded = json_decode((string)$response, true);
	return is_array($decoded) ? $decoded : ['status' => 'error', 'message' => 'Invalid JSON from Clearout'];
}

$result = ['ok' => true];

// Handle Email Finder
if ($action === 'find' || $action === 'both') {
	if ($name === '' || $domain === '') {
		http_response_code(400);
		echo json_encode(['ok' => false, 'error' => 'Missing name and/or domain for find']);
		exit;
	}
	$finderResp = call_clearout(
		'https://api.clearout.io/v2/email_finder/instant',
		[
			'name'    => $name,
			'domain'  => $domain,
			'queue'   => true,
			'timeout' => 30000,
		],
		$token
	);
	$result['find_raw'] = $finderResp;
	$found = $finderResp['data']['emails'][0]['email_address'] ?? null;
	if ($found) {
		$result['found_email'] = $found;
	}
}

// Handle Email Verify
if ($action === 'verify' || $action === 'both') {
	$targetEmail = $email;
	if ($action === 'both' && $targetEmail === '') {
		$targetEmail = $result['found_email'] ?? '';
	}
	if ($targetEmail === '') {
		http_response_code(400);
		echo json_encode(['ok' => false, 'error' => 'Missing email for verify']);
		exit;
	}
	$verifyResp = call_clearout(
		'https://api.clearout.io/v2/email_verify/instant',
		[
			'email'   => $targetEmail,
			'timeout' => 90000,
		],
		$token
	);
	$result['verify_raw'] = $verifyResp;
	$result['verdict'] = $verifyResp['data']['status'] ?? null; // valid | invalid | risky | unknown
	$result['score']   = $verifyResp['data']['score']  ?? null;
	$result['safe_to_send'] = $verifyResp['data']['safe_to_send'] ?? null;
}

echo json_encode($result);

// ---------------- UI renderer ----------------
function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function render_widget_ui(): void {
	$token = trim($_GET['token'] ?? '');
	$mode  = strtolower(trim($_GET['mode'] ?? 'manual')); // manual|find|verify|both
	$first = trim($_GET['first_name'] ?? '');
	$last  = trim($_GET['last_name'] ?? '');
	$name  = trim($_GET['name'] ?? (trim($first . ' ' . $last)));
	$domain = trim($_GET['domain'] ?? ($_GET['website'] ?? ''));
	$email  = trim($_GET['email'] ?? '');

	header('Content-Type: text/html; charset=utf-8');
	?>
<!doctype html>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Clearout Email Widget</title>
<style>
    * {
        box-sizing: border-box;
    }
    
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        margin: 0;
        padding: 16px;
        background: #f8f9fa;
        color: #333;
        line-height: 1.5;
    }

    .widget-container {
        background: white;
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        max-width: 500px;
        margin: 0 auto;
    }

    .widget-title {
        font-size: 18px;
        font-weight: 600;
        margin-bottom: 20px;
        color: #2c3e50;
        text-align: center;
    }

    .form-group {
        margin-bottom: 16px;
    }

    label {
        display: block;
        margin-bottom: 6px;
        font-weight: 500;
        color: #555;
        font-size: 14px;
    }

    input {
        width: 100%;
        padding: 10px 12px;
        border: 2px solid #e1e5e9;
        border-radius: 6px;
        font-size: 14px;
        transition: border-color 0.2s ease;
    }

    input:focus {
        outline: none;
        border-color: #007bff;
        box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
    }

    .button-group {
        display: flex;
        gap: 12px;
        margin-bottom: 16px;
        flex-wrap: wrap;
    }

    button {
        flex: 1;
        min-width: 120px;
        padding: 12px 16px;
        border: none;
        border-radius: 6px;
        font-size: 14px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s ease;
        text-align: center;
    }

    .btn-primary {
        background: #007bff;
        color: white;
    }

    .btn-primary:hover {
        background: #0056b3;
        transform: translateY(-1px);
    }

    .btn-secondary {
        background: #6c757d;
        color: white;
    }

    .btn-secondary:hover {
        background: #545b62;
        transform: translateY(-1px);
    }

    button:disabled {
        opacity: 0.6;
        cursor: not-allowed;
        transform: none !important;
    }

    .status {
        padding: 12px;
        border-radius: 6px;
        margin-bottom: 16px;
        font-size: 14px;
        font-weight: 500;
        text-align: center;
        display: none;
    }

    .status.loading {
        background: #e3f2fd;
        color: #1976d2;
        border: 1px solid #bbdefb;
        display: block;
    }

    .status.success {
        background: #e8f5e8;
        color: #2e7d32;
        border: 1px solid #c8e6c9;
        display: block;
    }

    .status.error {
        background: #ffebee;
        color: #c62828;
        border: 1px solid #ffcdd2;
        display: block;
    }

    .result-box {
        background: #f8f9fa;
        border: 1px solid #e9ecef;
        border-radius: 6px;
        padding: 12px;
        margin-top: 16px;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 12px;
        white-space: pre-wrap;
        max-height: 200px;
        overflow-y: auto;
        display: none;
    }

    .result-box.show {
        display: block;
    }

    .verdict {
        font-size: 16px;
        font-weight: 600;
        text-align: center;
        padding: 12px;
        border-radius: 6px;
        margin-top: 12px;
        display: none;
    }

    .verdict.valid {
        background: #d4edda;
        color: #155724;
        border: 1px solid #c3e6cb;
        display: block;
    }

    .verdict.invalid {
        background: #f8d7da;
        color: #721c24;
        border: 1px solid #f5c6cb;
        display: block;
    }

    .verdict.risky {
        background: #fff3cd;
        color: #856404;
        border: 1px solid #ffeaa7;
        display: block;
    }

    .verdict.unknown {
        background: #e2e3e5;
        color: #383d41;
        border: 1px solid #d6d8db;
        display: block;
    }

    .powered-by {
        text-align: center;
        color: #6c757d;
        font-size: 12px;
        margin-top: 16px;
        padding-top: 16px;
        border-top: 1px solid #e9ecef;
    }

    .spinner {
        display: inline-block;
        width: 16px;
        height: 16px;
        border: 2px solid #f3f3f3;
        border-top: 2px solid #007bff;
        border-radius: 50%;
        animation: spin 1s linear infinite;
        margin-right: 8px;
    }

    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
</style>

<div class="widget-container">
    <div class="widget-title">Email Verification Widget</div>
    
    <div class="form-group">
        <label for="name">Full Name</label>
        <input id="name" value="<?=h($name)?>" placeholder="John Doe" />
    </div>
    
    <div class="form-group">
        <label for="domain">Company Domain</label>
        <input id="domain" value="<?=h($domain)?>" placeholder="example.com" />
    </div>
    
    <div class="form-group">
        <label for="email">Email Address</label>
        <input id="email" value="<?=h($email)?>" placeholder="user@example.com" />
    </div>

    <div class="button-group">
        <button id="btnFind" class="btn-primary">
            <span class="btn-text">Find Email</span>
        </button>
        <button id="btnVerify" class="btn-secondary">
            <span class="btn-text">Verify Email</span>
        </button>
    </div>

    <div class="status" id="status"></div>
    <div class="verdict" id="verdict"></div>
    <div class="result-box" id="out"></div>
    
    <div class="powered-by">Powered by Clearout</div>
</div>

<script>
    // Read query params coming from Jotform widget settings mapping
    const qs = new URLSearchParams(location.search);
    const TOKEN = qs.get('token') || '<?=h($token)?>';
    const MODE = qs.get('mode') || '<?=h($mode)?>'; // 'find' | 'verify' | 'both' | 'manual'

    // Pre-fill fields from query params if provided
    const setVal = (id, val) => { if (val) document.getElementById(id).value = val; };
    setVal('name', '<?=h($name)?>' || (qs.get('name') || `${qs.get('first_name') || ''} ${qs.get('last_name') || ''}`).trim());
    setVal('domain', '<?=h($domain)?>' || qs.get('domain') || qs.get('website'));
    setVal('email', '<?=h($email)?>' || qs.get('email'));

    function showStatus(message, type = 'loading') {
        const status = document.getElementById('status');
        status.textContent = message;
        status.className = `status ${type}`;
    }

    function hideStatus() {
        document.getElementById('status').style.display = 'none';
    }

    function showVerdict(verdict, score = null) {
        const verdictEl = document.getElementById('verdict');
        const scoreText = score ? ` (Score: ${score})` : '';
        verdictEl.textContent = `${verdict.charAt(0).toUpperCase() + verdict.slice(1)}${scoreText}`;
        verdictEl.className = `verdict ${verdict}`;
    }

    function hideVerdict() {
        document.getElementById('verdict').style.display = 'none';
    }

    function setButtonLoading(buttonId, loading) {
        const btn = document.getElementById(buttonId);
        const btnText = btn.querySelector('.btn-text');
        if (loading) {
            btn.disabled = true;
            btnText.innerHTML = '<span class="spinner"></span>Processing...';
        } else {
            btn.disabled = false;
            btnText.textContent = buttonId === 'btnFind' ? 'Find Email' : 'Verify Email';
        }
    }

    function postToParent(payload) {
        // Generic postMessage that Jotform can listen for to set fields
        if (parent && parent !== window) {
            parent.postMessage({ type: 'clearout-widget', payload }, '*');
        }
        // If JFCustomWidget is available, use official API
        if (window.JFCustomWidget && typeof window.JFCustomWidget.sendDataToForm === 'function') {
            window.JFCustomWidget.sendDataToForm(payload);
        }
    }

    async function callEndpoint(action, data) {
        const body = { ...data, action };
        const headers = { 'Content-Type': 'application/json' };
        if (TOKEN) headers['Authorization'] = 'Bearer ' + TOKEN;
        
        // Use current URL as endpoint
        const url = TOKEN ? `${location.pathname}?token=${encodeURIComponent(TOKEN)}` : location.pathname;
        
        const res = await fetch(url, {
            method: 'POST',
            headers,
            body: JSON.stringify(body)
        });
        
        if (!res.ok) {
            const text = await res.text().catch(() => '');
            throw new Error('HTTP ' + res.status + (text ? ': ' + text : ''));
        }
        return res.json();
    }

    async function handleFind() {
        const out = document.getElementById('out');
        out.className = 'result-box';
        hideVerdict();
        showStatus('Searching for email address...', 'loading');
        setButtonLoading('btnFind', true);
        
        const name = document.getElementById('name').value.trim();
        const domain = document.getElementById('domain').value.trim();
        
        if (!name || !domain) {
            showStatus('Please enter both name and domain', 'error');
            setButtonLoading('btnFind', false);
            return;
        }
        
        try {
            const r = await callEndpoint('find', { name, domain });
            out.textContent = JSON.stringify(r, null, 2);
            out.classList.add('show');
            
            if (r.found_email) {
                document.getElementById('email').value = r.found_email;
                postToParent({ found_email: r.found_email });
                showStatus(`Email found: ${r.found_email}`, 'success');
            } else {
                showStatus('No email found for this name and domain', 'error');
            }
        } catch (e) {
            out.textContent = 'Error: ' + e.message;
            out.classList.add('show');
            showStatus('Error occurred while searching', 'error');
        } finally {
            setButtonLoading('btnFind', false);
        }
    }

    async function handleVerify() {
        const out = document.getElementById('out');
        out.className = 'result-box';
        hideVerdict();
        showStatus('Verifying email address...', 'loading');
        setButtonLoading('btnVerify', true);
        
        const email = document.getElementById('email').value.trim();
        
        if (!email) {
            showStatus('Please enter an email to verify', 'error');
            setButtonLoading('btnVerify', false);
            return;
        }
        
        try {
            const r = await callEndpoint('verify', { email });
            out.textContent = JSON.stringify(r, null, 2);
            out.classList.add('show');
            
            if (r.verdict) {
                showVerdict(r.verdict, r.score);
                hideStatus();
                
                postToParent({ 
                    verdict: r.verdict, 
                    score: r.score, 
                    safe_to_send: r.safe_to_send 
                });
            } else {
                showStatus('Verification failed - no result received', 'error');
            }
        } catch (e) {
            out.textContent = 'Error: ' + e.message;
            out.classList.add('show');
            showStatus('Error occurred while verifying', 'error');
        } finally {
            setButtonLoading('btnVerify', false);
        }
    }

    document.getElementById('btnFind').addEventListener('click', handleFind);
    document.getElementById('btnVerify').addEventListener('click', handleVerify);

    // Auto mode execution
    if (MODE === 'find') handleFind();
    if (MODE === 'verify') handleVerify();
    if (MODE === 'both') {
        (async () => { 
            await handleFind(); 
            await handleVerify(); 
        })();
    }
</script>
<?php }
