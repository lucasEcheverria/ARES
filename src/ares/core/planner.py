import json
import re
from dataclasses import dataclass
from typing import Any

import ollama

from .memory import TargetState
from .registry import registry


@dataclass
class PlannerResponse:
    """Structured output from a single LLM planning step.

    Attributes:
        thought: The LLM's reasoning about the current situation.
        action: Name of the tool the LLM decided to use.
        parameters: Arguments to pass to the tool.
        raw_response: Full LLM output, kept for debugging and reporting.
    """

    thought: str
    action: str
    parameters: dict[str, Any]
    raw_response: str


# System prompt sections follow ADR-005 ordering:
# Identity → Objective + format → Tools → Plan → Findings → Few-shot
_SYSTEM_IDENTITY = (
    "You are ARES, an autonomous penetration testing agent.\n"
    "Your goal is to perform methodical reconnaissance on a target system.\n"
    "You reason step by step and select the most appropriate tool "
    "for each situation.\n"
    "You only operate on systems you have explicit authorization to test."
)

_FORMAT_INSTRUCTIONS = (
    "After reasoning, you must respond in exactly this format:\n"
    "Thought: <your reasoning about what to do next>\n"
    "Action: <tool name>\n"
    "Parameters: <valid JSON object with tool parameters>\n\n"
    "If you believe the current phase is complete, use:\n"
    "Action: finish_phase\n"
    "Parameters: {}\n\n"
    "If you believe the full reconnaissance is complete, use:\n"
    "Action: finish\n"
    "Parameters: {}"
)

_FEW_SHOT = (
    "Example:\n"
    "Thought: I need to identify open ports on the target "
    "before enumerating services.\n"
    "Action: nmap\n"
    'Parameters: {"target": "192.168.1.1", "mode": "quick"}'
)


class Planner:
    """Handles all communication with the local LLM via Ollama.

    Builds the system prompt from the current TargetState, sends it to
    deepseek-r1:32b, and parses the response into a structured PlannerResponse.
    Implements a retry mechanism for malformed JSON in Parameters.
    """

    def __init__(self) -> None:
        self.model = "deepseek-r1:32b"
        self.registry = registry

    def plan(self, state: TargetState) -> PlannerResponse:
        """Run one planning step and return a structured decision.

        Calls the LLM with the current state and retries up to 2 times
        if the response cannot be parsed.

        Args:
            state: Current reconnaissance session state.

        Returns:
            Parsed PlannerResponse with thought, action and parameters.

        Raises:
            ValueError: If the response cannot be parsed after max retries.
        """
        prompt = self._build_prompt(state)
        max_retries = 2
        last_error: Exception | None = None

        for attempt in range(max_retries + 1):
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
            )
            # ollama Python client returns an object, not a dict.
            # content can be None if the model returns an empty response.
            raw: str = response.message.content or ""

            try:
                return self._parse_response(raw)
            except ValueError as e:
                last_error = e
                if attempt < max_retries:
                    # Append the error so the LLM can self-correct on retry.
                    prompt += (
                        f"\n\nYour previous response could not be parsed: {e}. "
                        "Please try again following the format exactly."
                    )

        raise ValueError(
            f"Failed to parse LLM response after {max_retries + 1} attempts: "
            f"{last_error}"
        )

    def _build_prompt(self, state: TargetState) -> str:
        """Serialize TargetState and assemble the full prompt.

        Follows ADR-005 section ordering to maximize LLM attention on
        critical information.

        Args:
            state: Current reconnaissance session state.

        Returns:
            Complete prompt string ready to send to the LLM.
        """
        tools_section = json.dumps(self.registry.schemas(), indent=2)

        checklist_lines = "\n".join(
            f"- [{item.status.value}] {item.question} (attempts: {item.attempts})"
            for item in state.phase_checklist
        )

        # Cap confirmed findings to last 10 to stay within token budget.
        findings_lines = "\n".join(
            f"- [{f.status.value}] {f.tool_name}: {f.result}"
            for f in state.confirmed[-10:]
        )

        return (
            f"{_SYSTEM_IDENTITY}\n\n"
            f"{_FORMAT_INSTRUCTIONS}\n\n"
            f"## Target\n"
            f"{state.raw_prompt}\n"
            f"Host: {state.target}\n"
            f"Context: {state.target_context or 'None provided'}\n\n"
            f"## Available Tools\n{tools_section}\n\n"
            f"## Current Phase: {state.current_phase.value}\n"
            f"### Checklist\n"
            f"{checklist_lines or 'No checklist items defined yet.'}\n\n"
            f"## Findings So Far\n"
            f"{findings_lines or 'No findings yet.'}\n\n"
            f"{_FEW_SHOT}"
        )

    def _parse_response(self, text: str) -> PlannerResponse:
        """Extract Thought, Action and Parameters from raw LLM output.

        deepseek-r1 wraps its internal reasoning in <think> tags before
        producing structured output. This method strips that block first,
        then extracts the three required fields.

        Args:
            text: Raw LLM response string.

        Returns:
            Parsed PlannerResponse.

        Raises:
            ValueError: If any required field is missing or Parameters
                is not valid JSON.
        """
        # Strip deepseek-r1 internal reasoning block if present.
        clean = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

        thought_match = re.search(r"Thought:\s*(.+?)(?=Action:|$)", clean, re.DOTALL)
        action_match = re.search(r"Action:\s*(\S+)", clean)
        params_match = re.search(r"Parameters:\s*(\{.*?\})", clean, re.DOTALL)

        if not thought_match:
            raise ValueError("Missing 'Thought' field in LLM response.")
        if not action_match:
            raise ValueError("Missing 'Action' field in LLM response.")
        if not params_match:
            raise ValueError("Missing 'Parameters' field in LLM response.")

        try:
            parameters: dict[str, Any] = json.loads(params_match.group(1))
        except json.JSONDecodeError as e:
            raise ValueError(f"Parameters is not valid JSON: {e}") from e

        return PlannerResponse(
            thought=thought_match.group(1).strip(),
            action=action_match.group(1).strip(),
            parameters=parameters,
            raw_response=text,
        )
