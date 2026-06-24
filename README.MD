<div align="center">

# ⚔️ ARES
### Autonomous Red-teaming & Exploitation System

*A locally-run LLM-powered autonomous pentesting agent*

![Status](https://img.shields.io/badge/status-v1.0%20stable-brightgreen?style=flat-square)
![Version](https://img.shields.io/badge/version-v1.0-blue?style=flat-square)
![Python](https://img.shields.io/badge/python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![LLM](https://img.shields.io/badge/LLM-Ollama%20local-black?style=flat-square)

</div>

---

## What is ARES?

ARES is an autonomous pentesting agent implementing the **ReAct** pattern (Reason + Act) using an LLM running entirely on-device via Ollama. The agent reasons about a target, iteratively selects and executes real security tools, maintains a persistent state of the target, and generates a professional report — including an LLM-written conclusion — at the end of each session.

The project was born as a learning tool and portfolio piece in the field of **offensive cybersecurity**, with a defined roadmap that evolves from a reconnaissance MVP to a full multi-agent system with persistent storage, a web dashboard, and integration with external vulnerability databases.

The agent loop looks like this:

Target → [Thought → Action → Observation] x N → Report

---

## v1.0 — Stable

Version 1.0 establishes the functional core of the agent and has been validated end-to-end against a real target:

- 🔍 **Automated reconnaissance** following a fixed pipeline: RECON → ENUMERATION → VULN_SCAN → REPORT
- 🧠 **ReAct loop** with native reasoning via `deepseek-r1:32b` running locally on Ollama
- 🛠️ **Real tools**: nmap, gobuster, nikto, curl — each wrapped with structured, uniform results
- 💾 **Session memory** with a compact, three-section target state (Objective / Plan / Findings)
- 📋 **Automatic final report** in Markdown, including a synthesized prose conclusion written by the LLM
- 🖥️ **CLI interface**

> ⚠️ **ARES is designed for use in controlled environments with explicit authorization. Do not use against systems you do not own or have permission to test.**

---

## Tech stack

| Component | Technology |
|---|---|
| Language | Python 3.12+ |
| Dependency management | uv |
| LLM | Ollama local — deepseek-r1:32b |
| Lab environment | Docker + Docker Compose (DVWA) |
| Testing | pytest |
| Linting | ruff + mypy |
| Documentation | MkDocs + Material |

---

## Setup

### Prerequisites

Install the following on your system:

```bash
# Ollama (LLM runtime)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull deepseek-r1:32b

# nikto (from source — no reliable package across distros)
sudo git clone https://github.com/sullo/nikto /opt/nikto
sudo ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto
sudo chmod +x /opt/nikto/program/nikto.pl

# gobuster (official binary, avoid outdated distro packages)
curl -LO https://github.com/OJ/gobuster/releases/latest/download/gobuster_Linux_x86_64.tar.gz
tar -xzf gobuster_Linux_x86_64.tar.gz
sudo mv gobuster /usr/local/bin/
```

`nmap` and `curl` are typically preinstalled or available directly through your distro's package manager.

### Project setup

```bash
git clone https://github.com/lucasEcheverria/ARES.git
cd ARES
uv sync
```

### Lab target (DVWA)

ARES ships with a ready-to-use vulnerable lab based on DVWA:

```bash
cd lab
docker compose up -d
```

Visit `http://localhost:8080`, log in with `admin` / `password`, and click **"Create / Reset Database"** the first time.

### Running ARES

```bash
uv run python -m ares.cli --target http://localhost:8080
```

Optional flags:

```bash
uv run python -m ares.cli --target http://localhost:8080 --max-iterations 30
```

The agent will reason through each phase, execute tools, and print its final report to stdout when done.

---

## Roadmap

ARES follows an incremental roadmap. v1.0 closes the reconnaissance-only MVP; from here, the project evolves toward persistence, a richer knowledge base, and a full multi-agent architecture.

**Coming in v1.1:** automated tests, structured logging, and centralized configuration — closing the gaps in observability that surfaced during v1.0's end-to-end testing.

Each version builds on the previous one without breaking existing functionality.

---

## Legal disclaimer

ARES is a research and learning project in offensive cybersecurity. Its use is intended exclusively for controlled environments, personal labs, and systems for which explicit authorization has been granted.

The author takes no responsibility for misuse of this tool.