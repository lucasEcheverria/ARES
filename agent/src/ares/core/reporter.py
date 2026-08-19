import re
from collections import defaultdict

import ollama

from .memory import Finding, Phase, TargetState

_REPORT_PROMPT = (
    "You are a senior penetration tester writing the final report for an "
    "authorized security assessment. Using ONLY the raw data provided "
    "below — never invent findings that are not backed by it — produce a "
    "complete, professional penetration testing report in GitHub-flavored "
    "Markdown.\n\n"
    "The report MUST contain exactly these four top-level sections, in "
    "this order, and nothing before or after them:\n\n"
    "## 1. Executive Summary\n"
    "Two to three paragraphs, written in full prose for a non-technical "
    "audience: what was tested, when, and with what methodology; a "
    "high-level conclusion on the target's overall security posture; and "
    "the most critical findings explained in plain language.\n\n"
    "## 2. Methodology\n"
    "A short description of the phases executed (Reconnaissance, "
    "Enumeration, Vulnerability Scanning) and the tools used in each, "
    "explaining in one sentence what each tool is for.\n\n"
    "## 3. Detailed Findings\n"
    "For each significant finding, include a heading with its title, a "
    "bolded severity label (one of **Critical**, **High**, **Medium**, "
    "**Low**, or **Info**), a detailed description written in full "
    "sentences, the evidence that supports it (quoting what the tool "
    "actually reported), and a concrete recommendation. Group related or "
    "duplicate findings together instead of repeating them, and interpret "
    "the raw tool output rather than just restating it. If a tool failed "
    "or found nothing, you may omit it or mention it briefly — do not "
    "invent a vulnerability to fill space.\n\n"
    "## 4. Conclusions and Recommendations\n"
    "A prioritized list of recommended remediation actions (most urgent "
    "first) and an overall risk assessment for the target.\n\n"
    "Use a Markdown table to summarize findings with their severities in "
    "section 3 if there is more than one finding. Write in professional "
    "English, in full sentences and paragraphs — this is a client "
    "deliverable, not a log dump.\n\n"
    "## Target\n"
    "Host: {target}\n"
    "Objective: {objective}\n\n"
    "## Phases Executed\n"
    "{phases}\n\n"
    "## Tools Used\n"
    "{tools}\n\n"
    "## Raw Findings (chronological, grouped by phase)\n"
    "{findings}\n"
)

_PHASE_DESCRIPTIONS: dict[Phase, str] = {
    Phase.RECON: "Reconnaissance — identifying open ports and running services.",
    Phase.ENUMERATION: (
        "Enumeration — discovering web paths, files, and confirming "
        "software versions."
    ),
    Phase.VULN_SCAN: (
        "Vulnerability Scanning — actively testing discovered surfaces "
        "for exploitable weaknesses."
    ),
}

_TOOL_PURPOSES: dict[str, str] = {
    "nmap": "network port and service discovery",
    "gobuster": "web directory and file brute-forcing",
    "nikto": "web server vulnerability and misconfiguration scanning",
    "sqlmap": "SQL injection detection",
    "curl": "manual inspection of individual HTTP endpoints",
    "whois": "domain registration lookup",
    "dig": "DNS record lookup",
    "openssl": "TLS/SSL certificate and cipher inspection",
    "testssl": "TLS/SSL configuration auditing",
    "whatweb": "web technology fingerprinting",
    "wpscan": "WordPress-specific vulnerability scanning",
    "zap_cli": "automated web application vulnerability scanning",
    "subfinder": "subdomain enumeration",
    "nuclei": "template-based vulnerability scanning",
}


class Reporter:
    """Generates the final penetration testing report from a completed session.

    Takes the full TargetState at the end of a ReAct session and asks the
    LLM to synthesize all recorded findings — confirmed and raw — into a
    structured, analytical Markdown report suitable for a client
    deliverable. Falls back to a plain enumeration of findings if the LLM
    call fails, so a report is always produced.
    """

    _PHASE_ORDER = [Phase.RECON, Phase.ENUMERATION, Phase.VULN_SCAN]

    def __init__(self) -> None:
        self.model = "deepseek-r1:32b"

    def generate(self, state: TargetState) -> str:
        """Generate a Markdown report from the session state.

        Args:
            state: Completed session state with all findings.

        Returns:
            Full report as a Markdown string.
        """
        tools_used = sorted({f.tool_name for f in state.raw})

        prompt = _REPORT_PROMPT.format(
            target=state.target,
            objective=state.raw_prompt,
            phases=self._build_phases_text(state),
            tools=self._build_tools_text(tools_used),
            findings=self._build_findings_text(state),
        )

        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"num_ctx": 32768},
            )
            body = self._strip_reasoning(response.message.content or "")
            body = self._strip_code_fence(body)
            if body:
                return f"{self._build_header(state)}\n\n{body}"
        except Exception as e:
            print(f"\n[!] Report generation failed, using fallback report: {e}")

        return self._fallback_report(state, tools_used)

    def _strip_reasoning(self, text: str) -> str:
        """Remove deepseek-r1's internal <think> reasoning block, if present.

        Args:
            text: Raw LLM response.

        Returns:
            Text with any <think>...</think> block removed, stripped.
        """
        return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    def _strip_code_fence(self, text: str) -> str:
        """Unwrap a single Markdown code fence wrapping the whole report.

        Some models return the requested Markdown document itself wrapped
        in a ```markdown ... ``` fence, as if presenting a code snippet.
        Saved verbatim, that fence makes the entire report render as one
        preformatted block instead of real headings and lists.

        Args:
            text: Report body after `<think>` removal.

        Returns:
            Text with a single outer fence removed, if the whole body was
            wrapped in one; otherwise unchanged.
        """
        match = re.match(r"^```(?:markdown|md)?\s*\n(.*)\n```\s*$", text, re.DOTALL)
        return match.group(1).strip() if match else text

    def _build_header(self, state: TargetState) -> str:
        """Build the report title and target section.

        Args:
            state: Completed session state.

        Returns:
            Markdown string for the header section.
        """
        return (
            "# ARES Penetration Testing Report\n\n"
            "## Target\n"
            f"- Host: {state.target}\n"
            f"- Objective: {state.raw_prompt}"
        )

    def _build_phases_text(self, state: TargetState) -> str:
        """Describe which pipeline phases actually ran, in fixed order.

        Args:
            state: Completed session state.

        Returns:
            Bullet list of executed phases with their goals, or a notice
            if none ran.
        """
        executed = {f.phase for f in state.raw}
        lines = [
            f"- {_PHASE_DESCRIPTIONS[phase]}"
            for phase in self._PHASE_ORDER
            if phase in executed
        ]
        if not lines:
            return "No phases were completed during this session."
        return "\n".join(lines)

    def _build_tools_text(self, tools_used: list[str]) -> str:
        """Describe each tool that ran and what it is used for.

        Args:
            tools_used: Sorted list of distinct tool names that ran.

        Returns:
            Bullet list of tools with their purpose, or a notice if none ran.
        """
        if not tools_used:
            return "No tools were executed during this session."
        default_purpose = "general-purpose security testing"
        return "\n".join(
            f"- **{tool}**: {_TOOL_PURPOSES.get(tool, default_purpose)}"
            for tool in tools_used
        )

    def _build_findings_text(self, state: TargetState) -> str:
        """Serialize every recorded finding, grouped by phase, in fixed order.

        Uses `state.raw`, which already contains every finding recorded
        during the session — both successful (also promoted to `confirmed`)
        and failed — so the LLM sees the complete picture.

        Args:
            state: Completed session state.

        Returns:
            Markdown-ish text listing all findings by phase, or a notice
            if none were recorded.
        """
        grouped: dict[Phase, list[Finding]] = defaultdict(list)
        for finding in state.raw:
            grouped[finding.phase].append(finding)

        lines: list[str] = []
        for phase in self._PHASE_ORDER:
            findings = grouped.get(phase, [])
            if not findings:
                continue
            lines.append(f"### {phase.value.upper()}")
            for finding in findings:
                lines.append(
                    f"- [{finding.status.value.upper()}] "
                    f"{finding.tool_name}: {finding.result}"
                )

        if not lines:
            return "No findings were recorded during this session."
        return "\n".join(lines)

    def _fallback_report(self, state: TargetState, tools_used: list[str]) -> str:
        """Build a plain, deterministic report when the LLM call fails.

        Args:
            state: Completed session state.
            tools_used: Sorted list of distinct tool names that ran.

        Returns:
            Full Markdown report enumerating raw findings without analysis.
        """
        grouped: dict[Phase, list[Finding]] = defaultdict(list)
        for finding in state.raw:
            grouped[finding.phase].append(finding)

        lines = [
            self._build_header(state),
            "\n## 1. Executive Summary",
            (
                "Automated analysis could not be generated for this session, "
                "so this document lists the raw findings collected without "
                "further interpretation. Each item below should be reviewed "
                "manually to assess its severity and impact."
            ),
            "\n## 2. Methodology",
            self._build_phases_text(state),
            "\n### Tools Used",
            self._build_tools_text(tools_used),
            "\n## 3. Detailed Findings",
        ]

        for phase in self._PHASE_ORDER:
            findings = grouped.get(phase, [])
            lines.append(f"\n### {phase.value.upper()}")
            if not findings:
                lines.append("No findings recorded for this phase.")
                continue
            for finding in findings:
                lines.append(
                    f"- **[{finding.status.value.upper()}] {finding.tool_name}**: "
                    f"{finding.result}"
                )

        lines.append(
            "\n## 4. Conclusions and Recommendations\n"
            "A prioritized, analytical risk assessment could not be "
            "generated automatically for this session. Manually review the "
            "findings above and prioritize remediation based on their "
            "severity and exploitability."
        )

        return "\n".join(lines)
