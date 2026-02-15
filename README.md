# mcpsek

**mcpsek** is a security scanning engine for MCP (Model Context Protocol) servers. Think VirusTotal for the MCP ecosystem — developers can check if an MCP server is safe before installing it.

## Features

- 🔍 **Automated Discovery**: Finds MCP servers from npm, PyPI, GitHub, and the official MCP registry
- 🔒 **Security Scanning**: Three comprehensive security checks:
  - **Tool Integrity**: Detects poisoned tool descriptions with hidden instructions
  - **Authentication Posture**: Checks for OAuth vs static keys vs no auth
  - **Endpoint Exposure**: Identifies network-accessible servers with security issues
- 📊 **Trust Scores**: 0-100 score based on security findings
- 🔄 **Mutation Detection**: Tracks when tool definitions change between scans
- 🌐 **REST API**: JSON API for programmatic access
- 🖥️ **Web Frontend**: Clean, minimal web UI for browsing results

## Tech Stack

- **Language**: Go 1.22+
- **Database**: PostgreSQL 16
- **Web Framework**: net/http + chi router
- **Templates**: Go html/template (server-rendered, no JavaScript frameworks)

## Quick Start

### Prerequisites

- Go 1.22 or higher
- PostgreSQL 16
- Git

### Installation

1. Clone the repository:
```bash
git clone https://github.com/mcpsek/mcpsek.git
cd mcpsek
```

2. Install dependencies:
```bash
make deps
```

3. Setup database:
```bash
make db-setup
```

4. Create configuration:
```bash
cp .env.example .env
# Edit .env with your settings
```

5. Run the server:
```bash
make run
```

The server will start on `http://localhost:8080` (or the port specified in your `.env` file).

## Configuration

mcpsek is configured via environment variables. See `.env.example` for all available options.

Key settings:
- `MCPSEK_DB_URL`: PostgreSQL connection string
- `MCPSEK_HTTP_ADDR`: Server address (default: `:8080`)
- `MCPSEK_SCAN_WORKERS`: Number of concurrent scanners (default: `4`)
- `MCPSEK_SCAN_INTERVAL`: How often to rescan servers (default: `24h`)
- `MCPSEK_DISCOVERY_INTERVAL`: How often to discover new servers (default: `168h` / 7 days)
- `MCPSEK_GITHUB_TOKEN`: Optional GitHub token for higher API rate limits

## API Endpoints

### Servers
- `GET /api/v1/servers` - List all servers (paginated)
- `GET /api/v1/servers/{id}` - Get server details with latest scan
- `GET /api/v1/servers/{id}/scans` - Get scan history for a server
- `GET /api/v1/servers/{id}/mutations` - Get mutation history for a server

### Search & Stats
- `GET /api/v1/search?q={query}` - Full-text search for servers
- `GET /api/v1/stats` - Global statistics
- `GET /api/v1/recent/critical` - Recently flagged critical servers
- `GET /api/v1/recent/mutations` - Recent mutations

### Response Format
```json
{
  "data": {...},
  "meta": {
    "total": 847,
    "page": 1,
    "per_page": 50,
    "timestamp": "2026-02-14T12:00:00Z"
  }
}
```

## How It Works

### Discovery
mcpsek continuously discovers MCP servers from multiple sources:
- **npm**: Searches for packages with "mcp-server" keywords
- **PyPI**: Searches for Python packages related to MCP
- **GitHub**: Finds repositories tagged with `mcp-server` topic
- **MCP Registry**: Pulls from the official registry (if available)

### Scanning Process

For each discovered server, mcpsek:

1. **Clones the repository** (shallow clone, cached)
2. **Extracts tool definitions** using regex patterns for TypeScript/JavaScript and Python
3. **Runs three security checks**:
   - **Tool Integrity**: Scans descriptions for hidden instructions, file exfiltration, data exfiltration, concealment instructions
   - **Authentication**: Detects OAuth, static keys, or no auth; scans for committed secrets
   - **Exposure**: Determines transport type (stdio vs network), checks bind address and TLS
4. **Computes trust score**: Starts at 100, subtracts penalties for findings
5. **Stores results** in PostgreSQL
6. **Detects mutations**: Compares tool definitions with previous scan

### Trust Score Calculation

Starting score: **100**

Penalties:
- Tool Integrity CRITICAL: -50
- Tool Integrity WARNING: -15
- Authentication CRITICAL: -35
- Authentication WARNING: -15
- Endpoint Exposure CRITICAL: -30
- Endpoint Exposure WARNING: -10

Floor: 0, Cap: 100

## Development

### Build
```bash
make build
```

### Run tests
```bash
make test
```

### Database management
```bash
make db-setup   # Create database and run migrations
make db-reset   # Drop and recreate database (DESTROYS DATA)
```

### Code formatting
```bash
make fmt
```

## Project Structure

```
mcpsek/
├── cmd/mcpsek/           # Main entry point
├── internal/
│   ├── api/              # REST API handlers
│   ├── config/           # Configuration
│   ├── database/         # Database layer
│   ├── discovery/        # Server discovery (npm, PyPI, GitHub)
│   ├── scanner/          # Security scanning engine
│   ├── scheduler/        # Background job scheduler
│   └── web/              # Web UI handlers + templates
├── migrations/           # Database schema
├── static/               # CSS and static assets
├── Makefile
└── README.md
```

## Security Checks Explained

### Check 1: Tool Integrity

**CRITICAL indicators:**
- Hidden instruction tags: `<IMPORTANT>`, `<SYSTEM>`, `<INSTRUCTION>`, etc.
- File exfiltration: `read ~/.ssh`, `read ~/.aws`, `cat ~/`, etc.
- Data exfiltration: `send to http`, suspicious URLs (webhook.site, ngrok.io)
- Concealment: `do not mention`, `keep this secret`, `hide this from`

**WARNING indicators:**
- Long descriptions (> 500 characters)
- Suspicious parameter names: `sidenote`, `hidden`, `internal`, `system_prompt`
- Cross-tool references: `before using, call X tool first`

### Check 2: Authentication Posture

**PASS**: OAuth 2.0 with token refresh and scoping

**WARNING**: Static secrets (API keys in env vars)

**CRITICAL**: No authentication OR committed secrets (AWS keys, GitHub PAT, private keys)

### Check 3: Endpoint Exposure

**PASS**: stdio transport OR localhost + TLS

**WARNING**: Network transport with either 0.0.0.0 bind OR no TLS

**CRITICAL**: Network transport + 0.0.0.0 bind + no TLS

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or pull request.

## Roadmap

- [ ] PyPI discovery implementation
- [ ] Cursor-based pagination for large datasets
- [ ] Real-time scanning via websockets
- [ ] Docker deployment support
- [ ] Comprehensive test suite
- [ ] CI/CD pipeline
- [ ] Performance benchmarks
- [ ] API authentication and rate limiting per user
