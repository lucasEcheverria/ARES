from typing import Any

from ..tools.base import BaseTool
from ..tools.curl import CurlTool
from ..tools.dig import DigTool
from ..tools.gobuster import GobusterTool
from ..tools.nikto import NiktoTool
from ..tools.nmap import NmapTool
from ..tools.nuclei import NucleiTool
from ..tools.openssl import OpensslTool
from ..tools.sqlmap import SqlmapTool
from ..tools.subfinder import SubfinderTool
from ..tools.testssl import TestsslTool
from ..tools.whatweb import WhatwebTool
from ..tools.whois import WhoisTool
from ..tools.wpscan import WpscanTool
from ..tools.zap_cli import ZapCliTool

from .memory import Phase

_PHASE_TOOLS: dict[Phase, list[str]] = {
    Phase.RECON: ["nmap", "subfinder", "whatweb", "dig", "whois", "openssl", "testssl"],
    Phase.ENUMERATION: ["gobuster", "nikto"],
    Phase.VULN_SCAN: ["sqlmap", "nuclei", "wpscan", "zap_cli", "curl"],
    Phase.REPORT: ["curl"],
}


class ToolRegistry:
    """Central registry for all available ARES tools.

    Provides a single access point for tool instances and their metadata,
    decoupling the agent from the concrete tool implementations.
    """

    # Tool instances are shared across the session — no state, safe to reuse.
    _tools: dict[str, BaseTool] = {
        "nmap": NmapTool(),
        "gobuster": GobusterTool(),
        "nikto": NiktoTool(),
        "curl": CurlTool(),
        "subfinder": SubfinderTool(),
        "testssl": TestsslTool(),
        "whatweb": WhatwebTool(),
        "dig": DigTool(),
        "whois": WhoisTool(),
        "openssl": OpensslTool(),
        "sqlmap": SqlmapTool(),
        "zap_cli": ZapCliTool(),
        "nuclei": NucleiTool(),
        "wpscan": WpscanTool(),
    }

    def get(self, name: str) -> BaseTool:
        """Return a tool instance by name.

        Args:
            name: The tool identifier, e.g. "nmap".

        Returns:
            The corresponding BaseTool instance.

        Raises:
            KeyError: If no tool with the given name is registered.
        """
        return self._tools[name]

    def schemas(self) -> list[dict[str, Any]]:
        """Return the metadata schema for all registered tools.

        Used by the planner to include available tools in the system prompt.

        Returns:
            List of schema dicts, one per registered tool.
        """
        return [tool.to_schema() for tool in self._tools.values()]
    
    def schemas_for_phase(self, phase: Phase) -> list[dict[str, Any]]:
        """Return tool schemas relevant to the given phase only.

        Reduces prompt size by excluding tools not applicable to the
        current phase, keeping the context window within budget.

        Args:
            phase: The current reconnaissance phase.

        Returns:
            List of schema dicts for tools available in this phase.
        """
        tool_names = _PHASE_TOOLS.get(phase, list(self._tools.keys()))
        return [
            self._tools[name].to_schema()
            for name in tool_names
            if name in self._tools
        ]


registry = ToolRegistry()
