<div align="center">

# ARES
### Autonomous Red-teaming & Exploitation System

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-9.x-005571?style=flat-square&logo=elasticsearch&logoColor=white)
![MariaDB](https://img.shields.io/badge/MariaDB-003545?style=flat-square&logo=mariadb&logoColor=white)
![Ollama](https://img.shields.io/badge/Ollama-deepseek--r1:32b-black?style=flat-square)

**An autonomous penetration testing agent powered by a local LLM, with a full web dashboard for session management, real-time execution monitoring and professional report generation.**

*Bachelor's Thesis (TFG) — Computer Engineering*

</div>

---

## What is ARES?

ARES is an autonomous penetration testing system that combines a local Large Language Model with a curated set of real security tools to perform reconnaissance and vulnerability assessment on a target — without human intervention at each step.

The agent implements the **ReAct (Reasoning + Acting)** pattern: it reasons about what to do next, selects the appropriate tool, executes it, observes the result, and iterates — exactly as a human pentester would think through a methodology, but autonomously.

The system is designed around three principles:

- **Autonomy** — the agent decides which tools to use, in which order, and when to move to the next phase, based on what it has found so far
- **Traceability** — every thought, action and result is persisted and visible in the dashboard in real time
- **Professionalism** — the final output is a structured penetration testing report written in natural language, not a raw tool dump

---

## How the agent works

### The ReAct loop

At its core, ARES is a loop. In each iteration, the agent:

1. **Thinks** — the LLM receives the current state (target, phase, findings so far) and reasons about what to do next, producing a `Thought` and an `Action`
2. **Acts** — the agent executes the chosen tool against the target via WSL
3. **Observes** — the tool result is added to the agent's memory
4. **Decides** — the agent either continues, moves to the next phase, or finishes

This loop runs for up to 100 iterations, covering four phases:

```
RECON ──────► ENUMERATION ──────► VULN_SCAN ──────► REPORT
```

### Phases and tools

Each phase has a specific goal and a restricted set of tools — the agent only sees the tools relevant to its current phase, which prevents it from using vulnerability scanners during reconnaissance or running port scanners during exploitation.

| Phase | Goal | Tools available |
|---|---|---|
| **RECON** | Identify open ports, services, subdomains, SSL config | nmap, subfinder, whatweb, dig, whois, openssl, testssl |
| **ENUMERATION** | Discover web paths, files, software versions | gobuster, nikto |
| **VULN_SCAN** | Test discovered paths for known vulnerabilities | sqlmap, nuclei, wpscan, zap_cli, curl |
| **REPORT** | Synthesize findings into a professional report | *(no tools — analysis only)* |

### Memory and state

The agent maintains a `TargetState` throughout its execution:

- **Objective** — the target, raw prompt, and any prior context about the target
- **Plan** — the current phase and per-phase checklists
- **Findings** — a confirmed findings list (never removed) and a raw findings buffer (capped at the last N entries to keep the context window manageable)

Confirmed findings are always included in every prompt, so the agent never "forgets" important discoveries. Raw findings rotate out to avoid prompt bloat.

### Persistence

Every action the agent takes is persisted to two separate stores with different purposes:

- **Elasticsearch** (`ares-logs` index): one document per tool result, with the full output split by line and tool-specific parsed fields (e.g. `found_paths` for gobuster, `open_ports` for nmap, `vulnerabilities` for nikto). This enables the logs table in the dashboard to filter by tool, phase, datetime range, and search within output content.

- **MariaDB** (`ares_sessions.events`): one row per agent action — thoughts, tool calls, and phase transitions — ordered by a monotonic `sequence` field. This is the data source for the execution graph in the dashboard.

At the end of a session, the agent saves the final report as a Markdown file to disk and stores the path in the database.

---

## The dashboard

The web dashboard is a React SPA that gives full visibility into ARES sessions — past and present.

### Authentication

Access is protected by Google OAuth 2.0. Users authenticate with their Google account; the server verifies the token, creates or updates the user record, and issues a JWT for subsequent API calls. Each user can only see their own sessions.

### Session management

The sidebar lists all sessions belonging to the authenticated user, with a visual indicator distinguishing sessions that are currently running from completed or failed ones. Creating a new session requires a name and a target — the server creates the session record, launches the agent as a background subprocess, and returns the session ID immediately. The UI transitions to the session view without waiting for the agent to finish.

### Agent tracking — real-time execution graph

The **Agent Tracking** tab shows the agent's execution as a horizontal node graph. Each node represents an action the agent took:

- **Thought nodes** — the LLM's reasoning at each step, showing a short preview with the full text on click
- **Tool call nodes** — the tool invoked and its parameters
- **Phase change nodes** — transitions between pipeline phases

While the session is running, new nodes appear automatically every few seconds as the agent works. When the session completes, the final graph is displayed in full. Nodes are color-coded by phase (green for RECON, purple for ENUMERATION, red for VULN_SCAN, amber for REPORT) and support zoom and pan for large graphs.

### Logs table — tool output browser

The **Report** page includes a logs section below the generated report that shows every tool result produced during the session. Each row shows the timestamp, phase, tool name, exit code, and a preview of the first lines of output. Clicking a row expands it to reveal the full output and the parsed metadata fields specific to that tool.

Logs can be filtered by phase, tool name, and datetime range, and the table updates automatically while the session is running.

### Report viewer

When the agent finishes, the generated Markdown report is fetched from the server and rendered in the dashboard with full formatting — headers, tables, bold text, code blocks. The report follows a professional penetration testing structure:

1. **Executive Summary** — overall security posture in plain language
2. **Methodology** — phases executed and tools used
3. **Detailed Findings** — each finding with title, severity, description, evidence and recommendation
4. **Conclusions and Recommendations** — prioritised action list

A free-text notes editor sits below the report for the analyst to add their own observations. Notes are saved per session.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Browser (React SPA)                   │
│  Login → Sidebar → Agent Graph │ Logs Table │ Report    │
└──────────────────────┬──────────────────────────────────┘
                       │ REST API + JWT
┌──────────────────────▼──────────────────────────────────┐
│                   FastAPI Server                         │
│  /auth  /sessions  /events  /logs  /report              │
│                                                          │
│  SQLAlchemy (async)    ES client (async)                 │
└──────┬─────────────────────┬───────────────────────────┘
       │                     │
       │ launches subprocess  │ reads
       ▼                     │
┌─────────────────┐          │
│   ARES Agent    │          │
│   ReAct loop    │          │
│                 │──────────┘
│  writes ──────► Elasticsearch (tool logs)
│  writes ──────► MariaDB ares_sessions (graph events)
│  writes ──────► Disk (Markdown report)
└─────────────────┘
       │
       ▼ via WSL2 Ubuntu
┌─────────────────────────────────────────────────────────┐
│  nmap · gobuster · nikto · sqlmap · nuclei · wpscan     │
│  subfinder · whatweb · dig · whois · openssl · testssl  │
│  zap_cli · curl                                         │
└─────────────────────────────────────────────────────────┘
```

### Monorepo structure

```
ares/
├── agent/          # Autonomous pentesting agent
│   └── src/ares/
│       ├── cli.py              # Entry point
│       ├── core/
│       │   ├── agent.py        # ReAct loop orchestration
│       │   ├── planner.py      # LLM prompt + response parsing
│       │   ├── memory.py       # TargetState, Phase, Finding types
│       │   ├── registry.py     # Tool registry with per-phase filtering
│       │   ├── reporter.py     # Professional report generation
│       │   ├── es_logger.py    # Elasticsearch log writer
│       │   └── graph_logger.py # MariaDB graph event writer
│       └── tools/              # 14 tool wrappers (BaseTool subclasses)
│
├── server/         # FastAPI REST API
│   ├── main.py
│   ├── config.py               # pydantic-settings from .env
│   ├── database/               # SQLAlchemy engines + ES client + init
│   ├── models/                 # ORM models (User, Session, Event)
│   ├── dao/                    # Data Access Objects
│   ├── services/               # Business logic + agent_runner.py
│   ├── routers/                # HTTP endpoints
│   └── scripts/seed_data.py    # Test data insertion
│
├── client/         # React SPA dashboard
│   └── src/
│       ├── types/              # TypeScript interfaces
│       ├── services/           # Real API calls (sessionsService, logsService)
│       ├── proxies/            # Data source abstraction
│       ├── controllers/        # React hooks (useAuth, useAgentTracking...)
│       ├── components/         # AgentGraph, LogsTable, NotesEditor...
│       ├── templates/          # AppLayout (responsive)
│       └── pages/              # LoginPage, NewSessionPage, ReportPage...
│
├── lib/            # Shared DTOs (future)
└── lab/            # Docker Compose — DVWA lab environment
```

---

## API reference

Full interactive documentation available at `http://localhost:8000/docs` when the server is running.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/google` | — | Verify Google id_token, return JWT |
| `POST` | `/sessions` | ✓ | Create session, launch agent in background |
| `GET` | `/sessions` | ✓ | List sessions for authenticated user |
| `GET` | `/sessions/{id}` | ✓ | Session detail with status |
| `GET` | `/sessions/{id}/events` | ✓ | Agent graph events from MariaDB |
| `GET` | `/sessions/{id}/logs` | ✓ | Tool logs from Elasticsearch (filterable) |
| `GET` | `/sessions/{id}/report` | ✓ | Generated Markdown report |

---

## Roadmap

| Version | Status | Description |
|---|---|---|
| v1.0 | ✅ | ReAct agent, 4 tools, CLI, end-to-end validated against DVWA |
| v1.2 | ✅ | 14 tools, WSL integration, per-phase tool filtering |
| v2.1 | ✅ | MariaDB persistence, session management, Google OAuth |
| v3.0 | ✅ | Full web dashboard, real-time graph, logs table, report viewer |
| v3.1 | 🔲 | Static knowledge base enrichment (CVEs, MITRE ATT&CK) |

---

## Installation and setup

<details>
<summary><b>Prerequisites</b></summary>

- Python 3.12+
- Node.js 20+
- `uv` — `pip install uv`
- Docker Desktop (for the lab)
- Ollama with `deepseek-r1:32b` — `ollama pull deepseek-r1:32b`
- MariaDB running locally
- Elasticsearch 9.x running locally (security disabled for development)
- WSL2 with Ubuntu

</details>

<details>
<summary><b>WSL2 tool installation</b></summary>

```bash
# Via apt
sudo apt install -y nmap gobuster nikto whatweb sqlmap curl dnsutils whois openssl

# Via Go
sudo apt install -y golang
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc

# testssl
git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/testssl
sudo ln -s ~/testssl/testssl.sh /usr/local/bin/testssl

# wpscan
sudo apt install -y ruby ruby-dev build-essential && sudo gem install wpscan

# OWASP ZAP
sudo snap install zaproxy --classic
sudo ln -s /snap/bin/zaproxy /usr/local/bin/zaproxy
```

</details>

<details>
<summary><b>Database setup</b></summary>

```sql
CREATE DATABASE ares_config CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE ares_sessions CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'ares'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON ares_config.* TO 'ares'@'localhost';
GRANT ALL PRIVILEGES ON ares_sessions.* TO 'ares'@'localhost';
FLUSH PRIVILEGES;
```

Tables are created automatically on first server startup.

</details>

<details>
<summary><b>Environment files</b></summary>

**`agent/.env`**
```env
ARES_REPORTS_DIR=../reports
ARES_ES_URL=http://localhost:9200
ARES_DB_HOST=localhost
ARES_DB_PORT=3306
ARES_DB_USER=ares
ARES_DB_PASSWORD=your_password
ARES_DB_SESSIONS=ares_sessions
```

**`server/.env`**
```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=ares
DB_PASSWORD=your_password
DB_CONFIG=ares_config
DB_SESSIONS=ares_sessions
ELASTICSEARCH_URL=http://localhost:9200
ARES_ES_URL=http://localhost:9200
GOOGLE_CLIENT_ID=your_google_client_id
JWT_SECRET=your_random_secret
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=10080
AGENT_PATH=/path/to/ares/agent
REPORTS_DIR=/path/to/ares/reports
```

**`client/.env`**
```env
VITE_GOOGLE_CLIENT_ID=your_google_client_id
VITE_API_URL=http://localhost:8000
```

</details>

<details>
<summary><b>Running ARES</b></summary>

```bash
# Terminal 1 — Elasticsearch
./bin/elasticsearch.bat  # Windows
./bin/elasticsearch      # Linux/Mac

# Terminal 2 — Server
cd server && uv run uvicorn main:app --reload

# Terminal 3 — Client
cd client && npm install && npm run dev

# Terminal 4 — Lab (optional)
cd agent && docker compose -f lab/docker-compose.yml up -d
```

Open `http://localhost:5173`, log in with Google, and create a new session.

</details>

<details>
<summary><b>Running the agent standalone (CLI)</b></summary>

```bash
cd agent
uv run python -m ares.cli --target http://localhost:8080
```

Options:
- `--target` — target URL, IP or hostname *(required)*
- `--max-iterations` — maximum ReAct iterations *(default: 100)*
- `--session-id` — set automatically when launched by the server

</details>

---

## License

MIT