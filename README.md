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
- Docker & Docker Compose (recommended)
- Git

### Installation

#### Option 1: Docker Setup (Recommended - Easiest!)

1. Clone the repository:
```bash
git clone https://github.com/mcpsek/mcpsek.git
cd mcpsek
```

2. Create configuration:
```bash
cp .env.example .env
```

3. Update `.env` with Docker database URL:
```bash
# Edit .env and set:
MCPSEK_DB_URL=postgres://mcpsek:mcpsek@localhost:5432/mcpsek?sslmode=disable
```

4. Start PostgreSQL with Docker:
```bash
docker-compose up -d
```

5. Wait for database to be ready and verify:
```bash
sleep 5
docker-compose exec postgres psql -U mcpsek -d mcpsek -c '\dt'
```

6. Run the server:
```bash
make run
```

The server will start on `http://localhost:8080`

#### Option 2: Local PostgreSQL Setup

1. Clone the repository:
```bash
git clone https://github.com/mcpsek/mcpsek.git
cd mcpsek
```

2. Install dependencies:
```bash
make deps
```

3. Setup local PostgreSQL database:
```bash
# Create database
createdb mcpsek

# Run migrations
make db-setup
```

4. Create configuration:
```bash
cp .env.example .env
# Edit .env with your PostgreSQL credentials
```

5. Run the server:
```bash
make run
```

## Configuration

mcpsek is configured via environment variables. See `.env.example` for all available options.

### Key Settings:

**Database (Required):**
- Docker: `MCPSEK_DB_URL=postgres://mcpsek:mcpsek@localhost:5432/mcpsek?sslmode=disable`
- Local: `MCPSEK_DB_URL=postgres://username:password@localhost:5432/mcpsek?sslmode=disable`

**Server:**
- `MCPSEK_HTTP_ADDR`: Server address (default: `:8080`)
- `MCPSEK_CLONE_DIR`: Directory for cloned repos (default: `/tmp/mcpsek-repos`)

**Scanning:**
- `MCPSEK_SCAN_WORKERS`: Concurrent scanners (default: `4`, increase for faster scanning)
- `MCPSEK_SCAN_INTERVAL`: Rescan frequency (default: `24h`)
- `MCPSEK_DISCOVERY_INTERVAL`: Discovery frequency (default: `168h` / 7 days)

**Optional:**
- `MCPSEK_GITHUB_TOKEN`: GitHub PAT for higher API rate limits (get one at https://github.com/settings/tokens)
- `MCPSEK_API_RATE_LIMIT`: API requests per minute (default: `100`)
- `MCPSEK_SHODAN_API_KEY`: For advanced exposure scanning

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

## Docker Commands

```bash
# Start PostgreSQL
docker-compose up -d

# View logs
docker-compose logs -f

# Stop PostgreSQL
docker-compose down

# Reset database (destroys all data)
docker-compose down -v
docker-compose up -d

# Access PostgreSQL shell
docker-compose exec postgres psql -U mcpsek -d mcpsek

# View database tables
docker-compose exec postgres psql -U mcpsek -d mcpsek -c '\dt'
```

## Troubleshooting

### Database Connection Issues

**Error: "password authentication failed"**
- Using Docker: Make sure `.env` has `MCPSEK_DB_URL=postgres://mcpsek:mcpsek@localhost:5432/mcpsek?sslmode=disable`
- Using local PostgreSQL: Update connection string with your username/password

**Error: "database does not exist"**
- Docker: Run `docker-compose down -v && docker-compose up -d`
- Local: Run `createdb mcpsek` then `make db-setup`

**Error: "connection refused"**
- Docker: Run `docker-compose ps` to check if PostgreSQL is running
- Local: Run `brew services start postgresql@16` (macOS) or `sudo systemctl start postgresql` (Linux)

## Roadmap

- [x] Docker deployment support
- [ ] PyPI discovery implementation
- [ ] Cursor-based pagination for large datasets
- [ ] Real-time scanning via websockets
- [ ] Comprehensive test suite
- [ ] CI/CD pipeline
- [ ] Performance benchmarks
- [ ] API authentication and rate limiting per user
