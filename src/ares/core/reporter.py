from collections import defaultdict

from .memory import Finding, Phase, TargetState


class Reporter:
    """Generates the final reconnaissance report from a completed session.

    Takes the full TargetState at the end of a ReAct session and produces
    a structured Markdown report with all confirmed findings organised by
    phase.
    """

    # Defines section ordering in the report — mirrors the pipeline order
    # from ADR-001, independent of dict iteration order.
    _PHASE_ORDER = [Phase.RECON, Phase.ENUMERATION, Phase.VULN_SCAN]

    def generate(self, state: TargetState) -> str:
        """Generate a Markdown report from the session state.

        Args:
            state: Completed session state with all findings.

        Returns:
            Full report as a Markdown string.
        """
        grouped = self._group_by_phase(state.confirmed)
        tools_used = sorted({f.tool_name for f in state.confirmed})

        sections = [
            self._build_header(state),
            self._build_summary(state, tools_used),
            self._build_findings(grouped),
        ]

        return "\n\n".join(sections)

    def _group_by_phase(self, findings: list[Finding]) -> dict[Phase, list[Finding]]:
        """Group findings by the pipeline phase in which they occurred.

        Args:
            findings: Flat list of findings to group.

        Returns:
            Dictionary mapping each phase to its list of findings.
        """
        grouped: dict[Phase, list[Finding]] = defaultdict(list)
        for finding in findings:
            grouped[finding.phase].append(finding)
        return grouped

    def _build_header(self, state: TargetState) -> str:
        """Build the report title and target section.

        Args:
            state: Completed session state.

        Returns:
            Markdown string for the header section.
        """
        return (
            "# ARES Reconnaissance Report\n\n"
            "## Target\n"
            f"- Host: {state.target}\n"
            f"- Objective: {state.raw_prompt}"
        )

    def _build_summary(self, state: TargetState, tools_used: list[str]) -> str:
        """Build the summary section with finding counts and tools used.

        Args:
            state: Completed session state.
            tools_used: Sorted list of distinct tool names that ran.

        Returns:
            Markdown string for the summary section.
        """
        tools_list = ", ".join(tools_used) if tools_used else "None"
        return (
            "## Summary\n"
            f"- Total findings: {len(state.confirmed)}\n"
            f"- Tools used: {tools_list}"
        )

    def _build_findings(self, grouped: dict[Phase, list[Finding]]) -> str:
        """Build the findings-by-phase section.

        Iterates phases in fixed pipeline order rather than dict order,
        so the report always reads RECON → ENUMERATION → VULN_SCAN
        regardless of insertion order.

        Args:
            grouped: Findings grouped by phase.

        Returns:
            Markdown string for the findings section.
        """
        lines = ["## Findings by Phase"]

        for phase in self._PHASE_ORDER:
            findings = grouped.get(phase, [])
            lines.append(f"\n### {phase.value.upper()}")

            if not findings:
                lines.append("No findings recorded for this phase.")
                continue

            for finding in findings:
                lines.append(f"- **{finding.tool_name}**: {finding.result}")

        return "\n".join(lines)
