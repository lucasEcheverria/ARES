from typing import Any

from ..tools.base import BaseTool
from ..tools.curl import CurlTool
from ..tools.gobuster import GobusterTool
from ..tools.nikto import NiktoTool
from ..tools.nmap import NmapTool


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


registry = ToolRegistry()
