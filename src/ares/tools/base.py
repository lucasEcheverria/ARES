import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ToolSuccess:
    """Successful result from a tool execution.

    Attributes:
        summary: Compact result summary for the LLM.
        output_raw: Full tool output for memory and reporting.
        tool_name: Name of the tool that generated the result.
        duration_seconds: Execution time in seconds.
    """

    summary: str
    output_raw: str
    tool_name: str
    duration_seconds: float


@dataclass
class ToolFailure:
    """Failed result from a tool execution.

    Attributes:
        error_message: Description of the error that occurred.
        output_raw: Partial tool output before the failure, if any.
        tool_name: Name of the tool that generated the failure.
        duration_seconds: Time elapsed before the failure, in seconds.
    """

    error_message: str
    output_raw: str | None
    tool_name: str
    duration_seconds: float


ToolResult = ToolSuccess | ToolFailure


class BaseTool(ABC):
    """Abstract base class for all ARES tool wrappers.

    Defines the contract that every wrapper must fulfill: parameter validation,
    tool execution, and result packaging into a uniform type that the agent
    can consume without knowing the underlying tool.

    Attributes:
        name: Unique tool identifier.
        description: Functional description for the LLM.
        params: Schema of accepted parameters as name-type key-value pairs.
    """

    name: str
    description: str
    params: dict[str, Any]

    def run(self, **kwargs: Any) -> ToolResult:
        """Execute the tool and return a structured result.

        Orchestrates validation, time measurement, and execution. Catches
        any unhandled exception and packages it as a ToolFailure so the
        ReAct loop is never interrupted by a tool failure.

        Args:
            **kwargs: Execution parameters specific to each tool.

        Returns:
            ToolSuccess with the result if execution succeeded,
            ToolFailure with the error if something went wrong.
        """
        self._validate(**kwargs)
        start = time.time()
        try:
            summary, raw_output = self._execute(**kwargs)
            duration = time.time() - start
            return ToolSuccess(
                summary=summary,
                output_raw=raw_output,
                tool_name=self.name,
                duration_seconds=duration,
            )
        except Exception as e:
            duration = time.time() - start
            return ToolFailure(
                error_message=str(e),
                output_raw=None,
                tool_name=self.name,
                duration_seconds=duration,
            )

    def to_schema(self) -> dict[str, Any]:
        """Serialize tool metadata for inclusion in the system prompt.

        Returns:
            Dictionary containing the tool's name, description and params.
        """
        return {
            "name": self.name,
            "description": self.description,
            "params": self.params,
        }

    @abstractmethod
    def _validate(self, **kwargs: Any) -> None:
        """Validate parameters before executing the tool.

        Args:
            **kwargs: Parameters to validate.

        Raises:
            ValueError: If a required parameter is missing or has an incorrect type.
        """
        ...

    @abstractmethod
    def _execute(self, **kwargs: Any) -> tuple[str, str]:
        """Execute the tool and return the result in two formats.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output) where summary is the compact text
            for the LLM and raw_output is the full output from the tool.
        """
        ...
