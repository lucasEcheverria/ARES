<div align="center">

# ⚔️ ARES
### Autonomous Red-teaming & Exploitation System

*Un agente de pentesting autónomo impulsado por LLM local*

![Estado](https://img.shields.io/badge/estado-en%20desarrollo-orange?style=flat-square)
![Versión](https://img.shields.io/badge/versión-v1.0--dev-blue?style=flat-square)
![Python](https://img.shields.io/badge/python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white)
![Licencia](https://img.shields.io/badge/licencia-MIT-green?style=flat-square)
![LLM](https://img.shields.io/badge/LLM-Ollama%20local-black?style=flat-square)

</div>

---

## ¿Qué es ARES?

ARES es un agente de pentesting autónomo que implementa el patrón **ReAct** (Reason + Act) usando un LLM ejecutado completamente en local via Ollama. El agente razona sobre un objetivo, selecciona y ejecuta herramientas reales de seguridad de forma iterativa, mantiene memoria del estado del objetivo y genera informes profesionales al finalizar.

El proyecto nace como herramienta de aprendizaje y portfolio en el ámbito de la **ciberseguridad ofensiva**, con un roadmap definido que evoluciona desde un MVP de reconocimiento hasta un sistema multi-agente con interfaz web completa.
```
Objetivo → [Thought → Action → Observation] × N → Informe
               └─────────── ReAct loop ───────────┘
```

---

## Estado actual — v1.0 (en desarrollo)

La versión 1.0 establece el núcleo funcional del agente:

- 🔍 **Reconocimiento automatizado** sobre un único objetivo controlado (DVWA)
- 🧠 **Bucle ReAct** con razonamiento nativo via `deepseek-r1:32b` en Ollama
- 🛠️ **Herramientas reales**: nmap, gobuster, nikto, curl
- 💾 **Memoria de sesión** con estado compacto del objetivo
- 📋 **Informe final** generado automáticamente al terminar la sesión
- 🖥️ **Interfaz CLI** exclusivamente

> ⚠️ **ARES está diseñado para uso en entornos controlados y con autorización explícita.
> No utilizar contra sistemas sin permiso.**

---

## Stack tecnológico

| Componente | Tecnología |
|---|---|
| Lenguaje | Python 3.12+ |
| Gestión de dependencias | uv |
| LLM | Ollama local — deepseek-r1:32b |
| Laboratorio | Docker + Docker Compose |
| Testing | pytest |
| Linting | ruff + mypy |
| Documentación | MkDocs + Material |

---

## Roadmap

ARES sigue un roadmap incremental con versiones bien definidas. El punto de partida es un agente CLI de reconocimiento; la visión final es un sistema completo de red team autónomo con arquitectura multi-agente, persistencia, dashboard web en tiempo real y capacidad de operar sobre múltiples objetivos simultáneamente.

Cada versión construye sobre la anterior sin romper lo existente.

---

## Setup

> 📖 Las instrucciones de instalación y configuración estarán disponibles cuando v1.0 esté completa.

---

## Aviso legal

ARES es un proyecto de investigación y aprendizaje en ciberseguridad ofensiva.
Su uso está destinado exclusivamente a entornos controlados, laboratorios propios
y sistemas sobre los que se tiene autorización explícita.

El autor no se hace responsable del uso indebido de esta herramienta.
