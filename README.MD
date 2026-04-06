<div align="center">

# ⚔️ ARES
### Autonomous Red-teaming & Exploitation System

*A locally-run LLM-powered autonomous pentesting agent*

![Status](https://img.shields.io/badge/status-in%20development-orange?style=flat-square)
![Version](https://img.shields.io/badge/version-v1.0--dev-blue?style=flat-square)
![Python](https://img.shields.io/badge/python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![LLM](https://img.shields.io/badge/LLM-Ollama%20local-black?style=flat-square)

</div>

---

## What is ARES?

ARES is an autonomous pentesting agent implementing the **ReAct** pattern
(Reason + Act) using an LLM running entirely on-device via Ollama. The agent
reasons about a target, iteratively selects and executes real security tools,
maintains a persistent state of the target, and generates a professional report
at the end of each session.

The project was born as a learning tool and portfolio piece in the field of
**offensive cybersecurity**, with a defined roadmap that evolves from a
reconnaissance MVP to a full multi-agent system with a complete web interface.
```
Target → [Thought → Action → Observation] × N → Report
            └─────────── ReAct loop ───────────┘
```

---

## Current status — v1.0 (in development)

Version 1.0 establishes the functional core of the agent:

- 🔍 **Automated reconnaissance** against a single controlled target (DVWA)
- 🧠 **ReAct loop** with native reasoning via `deepseek-r1:32b` on Ollama
- 🛠️ **Real tools**: nmap, gobuster, nikto, curl
- 💾 **Session memory** with compact target state tracking
- 📋 **Automatic final report** generated at the end of each session
- 🖥️ **CLI-only interface**

> ⚠️ **ARES is designed for use in controlled environments with explicit
> authorization. Do not use against systems you do not own or have permission
> to test.**

---

## Tech stack

| Component | Technology |
|---|---|
| Language | Python 3.12+ |
| Dependency management | uv |
| LLM | Ollama local — deepseek-r1:32b |
| Lab environment | Docker + Docker Compose |
| Testing | pytest |
| Linting | ruff + mypy |
| Documentation | MkDocs + Material |

---

## Roadmap

ARES follows an incremental roadmap with clearly defined versions. The starting
point is a CLI reconnaissance agent; the final vision is a complete autonomous
red team system with a multi-agent architecture, persistent storage, a real-time
web dashboard, and the ability to operate against multiple targets simultaneously.

Each version builds on the previous one without breaking existing functionality.

---

## Setup

> 📖 Installation and configuration instructions will be available once v1.0
> is complete.

---

## Legal disclaimer

ARES is a research and learning project in offensive cybersecurity.
Its use is intended exclusively for controlled environments, personal labs,
and systems for which explicit authorization has been granted.

The author takes no responsibility for misuse of this tool.