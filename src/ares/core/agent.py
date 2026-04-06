from datetime import UTC, datetime

from ..tools.base import ToolSuccess
from .memory import (
    Finding,
    FindingStatus,
    Phase,
    TargetState,
)
from .planner import Planner, PlannerResponse
from .registry import registry


class Agent:
    """Orchestrates the full ReAct loop for a single reconnaissance session.

    Connects the planner, tool registry and session state to implement
    the Thought → Action → Observation cycle defined in ADR-004.
    """

    MAX_ITERATIONS = 50

    def __init__(self) -> None:
        self.planner = Planner()
        self.registry = registry

    def run(self, state: TargetState) -> str:
        """Execute the ReAct loop until the agent finishes or hits the limit.

        Each iteration asks the planner what to do, executes the chosen
        action, and updates the session state. Stops when the agent emits
        'finish' or MAX_ITERATIONS is reached.

        Args:
            state: Initial session state with target and objective.

        Returns:
            Final markdown report as a string.
        """
        for iteration in range(self.MAX_ITERATIONS):
            print(f"\n[iteration {iteration + 1}/{self.MAX_ITERATIONS}]")

            response = self.planner.plan(state)

            # Print the LLM reasoning so the user can follow along in the CLI.
            print(f"Thought: {response.thought}")
            print(f"Action: {response.action}")

            should_stop = self._handle_action(state, response)
            if should_stop:
                break
        else:
            # Loop exhausted without a finish signal — report what we have.
            print(
                "\n[!] Iteration limit reached. "
                "Generating report with current findings."
            )

        # Reporter will be wired here once implemented.
        return ""

    def _handle_action(self, state: TargetState, response: PlannerResponse) -> bool:
        """Dispatch one action and update state accordingly.

        Args:
            state: Current session state, mutated in place.
            response: Parsed LLM decision for this iteration.

        Returns:
            True if the loop should stop, False to continue.
        """
        if response.action == "finish":
            print("\n[✓] Agent decided reconnaissance is complete.")
            return True

        if response.action == "finish_phase":
            self._advance_phase(state)
            return False

        # Any other action is treated as a tool call.
        self._execute_tool(state, response)
        return False

    def _execute_tool(self, state: TargetState, response: PlannerResponse) -> None:
        """Run the requested tool and persist the result in session state.

        Looks up the tool by name, executes it with the parameters the LLM
        provided, and appends the outcome to state.raw as a Finding. If the
        tool name is not registered, appends a FAIL finding instead of
        raising an exception — the agent must never crash on a bad tool call.

        Args:
            state: Current session state, mutated in place.
            response: Parsed LLM decision containing tool name and parameters.
        """
        try:
            tool = self.registry.get(response.action)
        except KeyError:
            # Unknown tool — log it as a failed finding so the LLM can react.
            state.raw.append(
                Finding(
                    tool_name=response.action,
                    phase=state.current_phase,
                    status=FindingStatus.FAIL,
                    result=f"Unknown tool: '{response.action}'",
                    timestamp=datetime.now(UTC),
                )
            )
            return

        # Unpack parameters as keyword arguments — matches BaseTool.run() signature.
        result = tool.run(**response.parameters)

        finding = Finding(
            tool_name=response.action,
            phase=state.current_phase,
            # ToolSuccess and ToolFailure are the two possible ToolResult types.
            status=FindingStatus.SUCCESS
            if isinstance(result, ToolSuccess)
            else FindingStatus.FAIL,
            result=result.summary
            if isinstance(result, ToolSuccess)
            else result.error_message,
            timestamp=datetime.now(UTC),
        )

        state.raw.append(finding)

        # Also promote to confirmed if the tool succeeded — permanent memory.
        if isinstance(result, ToolSuccess):
            state.confirmed.append(finding)

        print(f"Observation: {finding.result}")

    def _advance_phase(self, state: TargetState) -> None:
        """Move to the next pipeline phase or stop if already on REPORT.

        Phase order follows ADR-001: RECON → ENUMERATION → VULN_SCAN → REPORT.
        REPORT is the terminal phase — advancing from it signals completion.

        Args:
            state: Current session state, mutated in place.
        """
        phase_order = [
            Phase.RECON,
            Phase.ENUMERATION,
            Phase.VULN_SCAN,
            Phase.REPORT,
        ]

        current_index = phase_order.index(state.current_phase)

        if current_index < len(phase_order) - 1:
            next_phase = phase_order[current_index + 1]
            print(
                f"\n[→] Advancing phase: "
                f"{state.current_phase.value} → {next_phase.value}"
            )
            state.current_phase = next_phase
            # Reset phase checklist on phase entry — new phase, new goals.
            state.phase_checklist = []
        else:
            # Already on REPORT — nothing left to advance to.
            print("\n[✓] All phases complete.")
