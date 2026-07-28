"""Writes tool_result logs to Elasticsearch.

Encapsulates the Elasticsearch client and per-tool output parsing so
agent.py only has to import log_tool_result() and call it. Never raises —
any connection or indexing failure is logged and swallowed so a missing
or unreachable Elasticsearch cluster never crashes the agent.
"""

import logging
import os
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from elasticsearch import Elasticsearch

from ..tools.base import ToolResult, ToolSuccess
from .memory import TargetState

logger = logging.getLogger(__name__)

INDEX = "ares-logs"

_NMAP_PORT_LINE = re.compile(r"^(\d+)/(?:tcp|udp)\s+(\S+)\s+(\S+)")

_client: Elasticsearch | None = None


def _get_client() -> Elasticsearch:
    global _client
    if _client is None:
        url = os.environ.get("ARES_ES_URL", "http://localhost:9200")
        _client = Elasticsearch(url)
    return _client


def _parse_gobuster(lines: list[str]) -> dict[str, Any]:
    found_paths = []
    for line in lines:
        if "(Status:" in line:
            path = line.split("(Status:")[0].strip()
            if path and not path.startswith("/"):
                path = f"/{path}"
            if path:
                found_paths.append(path)
    return {"found_paths": found_paths}


def _parse_nmap(lines: list[str]) -> dict[str, Any]:
    open_ports: list[int] = []
    services: dict[str, str] = {}
    for line in lines:
        match = _NMAP_PORT_LINE.match(line.strip())
        if match and match.group(2) == "open":
            port = int(match.group(1))
            open_ports.append(port)
            services[str(port)] = match.group(3)
    return {"open_ports": open_ports, "services": services}


def _parse_nikto(lines: list[str]) -> dict[str, Any]:
    vulnerabilities = [
        line.strip()
        for line in lines
        if line.strip().startswith("+ ") and "Server" not in line
    ]
    return {"vulnerabilities": vulnerabilities}


def _parse_sqlmap(lines: list[str]) -> dict[str, Any]:
    injectable_params: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("Parameter:"):
            param = stripped[len("Parameter:") :].strip().split(" ")[0]
            if param and param not in injectable_params:
                injectable_params.append(param)
    return {"injectable_params": injectable_params}


_METADATA_PARSERS = {
    "gobuster": _parse_gobuster,
    "nmap": _parse_nmap,
    "nikto": _parse_nikto,
    "sqlmap": _parse_sqlmap,
}


def _extract_metadata(tool_name: str, lines: list[str]) -> dict[str, Any]:
    parser = _METADATA_PARSERS.get(tool_name)
    return parser(lines) if parser else {}


def log_tool_result(state: TargetState, tool_name: str, result: ToolResult) -> None:
    """Index a tool_result document into the `ares-logs` Elasticsearch index.

    Args:
        state: Current session state — used for session_id and phase.
        tool_name: Name of the tool that produced the result.
        result: ToolSuccess or ToolFailure returned by BaseTool.run().
    """
    raw_output = result.output_raw if isinstance(result, ToolSuccess) else (
        result.output_raw or ""
    )
    exit_code = 0 if isinstance(result, ToolSuccess) else 1
    lines = [line for line in raw_output.splitlines() if line.strip()]

    document = {
        "id": str(uuid.uuid4()),
        "session_id": state.session_id,
        "phase": state.current_phase.value.upper(),
        "tool": tool_name,
        "created_at": datetime.now(UTC).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        ),
        "exit_code": exit_code,
        "lines": lines,
        "metadata": _extract_metadata(tool_name, lines),
    }

    try:
        client = _get_client()
        client.index(index=INDEX, id=document["id"], document=document)
    except Exception:
        logger.exception(
            "Failed to write tool_result log to Elasticsearch for tool '%s'",
            tool_name,
        )
