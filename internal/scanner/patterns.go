package scanner

import "regexp"

// Compiled regex patterns for security checks
var (
	// ====== TOOL INTEGRITY PATTERNS ======

	// Tool definition extraction patterns (TypeScript/JavaScript)
	toolDefServerToolPattern = regexp.MustCompile(`(?i)server\.tool\s*\(\s*["']([^"']+)["']\s*,\s*["'\x60]([\s\S]*?)["'\x60]\s*,`)
	toolDefObjectPattern     = regexp.MustCompile(`(?i)\{\s*name\s*:\s*["']([^"']+)["']\s*,\s*description\s*:\s*["'\x60]([\s\S]*?)["'\x60]`)
	toolDefToolPattern       = regexp.MustCompile(`(?i)Tool\s*\(\s*\{[^}]*name\s*:\s*["']([^"']+)["'][^}]*description\s*:\s*["'\x60]([\s\S]*?)["'\x60]`)

	// Tool definition extraction patterns (Python)
	pythonDecoratorPattern = regexp.MustCompile(`(?i)@(?:server|mcp)\.tool\(\)[\s\S]*?def\s+(\w+)[\s\S]*?"""([\s\S]*?)"""`)
	pythonToolPattern      = regexp.MustCompile(`(?i)Tool\(\s*name\s*=\s*["']([^"']+)["']\s*,\s*description\s*=\s*["']([\s\S]*?)["']`)

	// CRITICAL indicators - hidden instruction tags
	hiddenInstructionPattern = regexp.MustCompile(`(?i)<(IMPORTANT|SYSTEM|INSTRUCTION|ADMIN|OVERRIDE|HIDDEN|SECRET|INTERNAL|PRIORITY|CRITICAL|NOTE|WARNING|CONTEXT|REMINDER|RULE)\b[^>]*>`)

	// CRITICAL indicators - file exfiltration
	fileExfiltrationPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)read.*~/`),
		regexp.MustCompile(`(?i)read.*~/\.ssh`),
		regexp.MustCompile(`(?i)read.*~/\.aws`),
		regexp.MustCompile(`(?i)read.*~/\.env`),
		regexp.MustCompile(`(?i)read.*~/\.cursor`),
		regexp.MustCompile(`(?i)read.*~/\.claude`),
		regexp.MustCompile(`(?i)read.*/etc/passwd`),
		regexp.MustCompile(`(?i)cat\s+~/`),
		regexp.MustCompile(`(?i)open\s+~/`),
		regexp.MustCompile(`(?i)content.*of.*\.env`),
		regexp.MustCompile(`(?i)pass.*as.*sidenote`),
		regexp.MustCompile(`(?i)include.*credentials`),
		regexp.MustCompile(`(?i)send.*config`),
		regexp.MustCompile(`(?i)read.*mcp\.json`),
	}

	// CRITICAL indicators - data exfiltration URLs
	dataExfiltrationPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(send|post|transmit|forward|upload|exfiltrate).*to.*http`),
		regexp.MustCompile(`https?://[^\s"']+\.(tk|ml|ga|cf|gq)`),
		regexp.MustCompile(`(?i)webhook\.site`),
		regexp.MustCompile(`(?i)requestbin`),
		regexp.MustCompile(`(?i)ngrok\.io`),
		regexp.MustCompile(`(?i)burpcollaborator`),
	}

	// CRITICAL indicators - concealment instructions
	concealmentPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)do not (mention|tell|inform|show|display|reveal)`),
		regexp.MustCompile(`(?i)don't (mention|tell|inform|show|display|reveal)`),
		regexp.MustCompile(`(?i)keep.*(secret|hidden|confidential)`),
		regexp.MustCompile(`(?i)this is confidential`),
		regexp.MustCompile(`(?i)be gentle and not scary`),
		regexp.MustCompile(`(?i)user (should|must) not (know|see)`),
		regexp.MustCompile(`(?i)hide this from`),
		regexp.MustCompile(`(?i)invisible to the user`),
	}

	// WARNING indicators - suspicious parameter names
	suspiciousParamPattern = regexp.MustCompile(`(?i)\b(sidenote|context|note|extra|metadata|hidden|internal|system_prompt|instruction)\b`)

	// WARNING indicators - cross-tool references
	crossToolRefPattern = regexp.MustCompile(`(?i)(before|first|prior).*call\s+\w+|(must|should|always).*use\s+\w+\s+(tool|function|first)|call\s+\w+\s+before`)

	// ====== AUTHENTICATION POSTURE PATTERNS ======

	// OAuth 2.0 indicators (PASS)
	oauthPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\boauth\b`),
		regexp.MustCompile(`(?i)authorization_code`),
		regexp.MustCompile(`(?i)\bpkce\b`),
		regexp.MustCompile(`(?i)token_endpoint`),
		regexp.MustCompile(`(?i)refresh_token`),
		regexp.MustCompile(`(?i)OAuthProvider`),
		regexp.MustCompile(`(?i)authorizationUrl`),
		regexp.MustCompile(`(?i)tokenUrl`),
		regexp.MustCompile(`(?i)import.*authlib`),
		regexp.MustCompile(`(?i)import.*passport`),
		regexp.MustCompile(`(?i)import.*oauth`),
		regexp.MustCompile(`(?i)from.*oauth`),
		regexp.MustCompile(`(?i)grant_type`),
	}

	// Static secrets indicators (WARNING)
	staticSecretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)process\.env\.(API_KEY|TOKEN|SECRET|PAT|PERSONAL_ACCESS_TOKEN|ACCESS_TOKEN)`),
		regexp.MustCompile(`(?i)os\.environ\[.*(API_KEY|TOKEN|SECRET|PAT|PERSONAL_ACCESS_TOKEN|ACCESS_TOKEN)`),
		regexp.MustCompile(`(?i)os\.getenv\(.*(API_KEY|TOKEN|SECRET|PAT|PERSONAL_ACCESS_TOKEN|ACCESS_TOKEN)`),
		regexp.MustCompile(`(?i)BEARER_TOKEN`),
		regexp.MustCompile(`(?i)X-API-Key`),
		regexp.MustCompile(`(?i)Authorization.*Bearer`),
		regexp.MustCompile(`(?i)"apiKey"`),
		regexp.MustCompile(`(?i)"token"`),
		regexp.MustCompile(`(?i)"personalAccessToken"`),
	}

	// Committed secrets patterns
	awsKeyPattern     = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	githubPatPattern  = regexp.MustCompile(`ghp_[A-Za-z0-9_]{36}`)
	githubPat2Pattern = regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`)
	privateKeyPattern = regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)
	slackTokenPattern = regexp.MustCompile(`xox[bp]-[0-9]{11,12}-[0-9]{11,12}-[a-zA-Z0-9]{24}`)
	genericKeyPattern = regexp.MustCompile(`["']sk-[a-zA-Z0-9]{20,}["']`)

	// ====== ENDPOINT EXPOSURE PATTERNS ======

	// stdio indicators (safest)
	stdioPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)StdioServerTransport`),
		regexp.MustCompile(`(?i)stdio_server`),
		regexp.MustCompile(`(?i)server\.stdio`),
		regexp.MustCompile(`(?i)transport.*stdio`),
		regexp.MustCompile(`(?i)"type"\s*:\s*"stdio"`),
	}

	// Network transport indicators (risk)
	networkTransportPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)SSEServerTransport`),
		regexp.MustCompile(`(?i)sse_server`),
		regexp.MustCompile(`(?i)server\.sse`),
		regexp.MustCompile(`(?i)createServer.*listen`),
		regexp.MustCompile(`(?i)app\.listen\(`),
		regexp.MustCompile(`(?i)\bexpress\(\)`),
		regexp.MustCompile(`(?i)\bfastify\b`),
		regexp.MustCompile(`(?i)\bflask\b`),
		regexp.MustCompile(`(?i)FastAPI`),
		regexp.MustCompile(`(?i)uvicorn`),
		regexp.MustCompile(`(?i)\.listen\(PORT`),
		regexp.MustCompile(`(?i)http\.createServer`),
		regexp.MustCompile(`(?i)\bHono\b`),
		regexp.MustCompile(`(?i)WebSocketServerTransport`),
		regexp.MustCompile(`(?i)ws_server`),
		regexp.MustCompile(`(?i)websocket`),
		regexp.MustCompile(`(?i)wss://`),
	}

	// Bind address patterns
	bindAllPattern      = regexp.MustCompile(`(?i)0\.0\.0\.0|INADDR_ANY|host\s*:\s*""\s*[,}]`)
	bindLocalhostPattern = regexp.MustCompile(`(?i)127\.0\.0\.1|localhost|::1`)

	// TLS indicators
	tlsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bhttps\b`),
		regexp.MustCompile(`(?i)\btls\b`),
		regexp.MustCompile(`(?i)\bssl\b`),
		regexp.MustCompile(`(?i)\bcert\b`),
		regexp.MustCompile(`(?i)certificate`),
		regexp.MustCompile(`(?i)key\.pem`),
		regexp.MustCompile(`(?i)cert\.pem`),
		regexp.MustCompile(`(?i)createSecureServer`),
		regexp.MustCompile(`(?i)ssl_context`),
	}

	// Port extraction pattern
	portPattern = regexp.MustCompile(`(?i)\.listen\(\s*(\d+)|port\s*[:=]\s*(\d+)|PORT\s*=\s*(\d+)|--port\s+(\d+)`)
)

// File extensions to scan
var scanExtensions = map[string]bool{
	".ts":   true,
	".tsx":  true,
	".js":   true,
	".jsx":  true,
	".mjs":  true,
	".py":   true,
	".json": true,
	".yaml": true,
	".yml":  true,
}

// Directories to skip
var skipDirs = map[string]bool{
	"node_modules": true,
	"venv":         true,
	".venv":        true,
	"__pycache__":  true,
	".git":         true,
	"dist":         true,
	"build":        true,
	".next":        true,
	"coverage":     true,
	".pytest_cache": true,
}
