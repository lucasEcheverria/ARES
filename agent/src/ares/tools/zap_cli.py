import json
import subprocess
import uuid
from typing import Any

from .base import WSL_PREFIX, BaseTool


class ZapCliTool(BaseTool):
    """Wrapper for OWASP ZAP's headless command-line quick scan.

    Runs the `zaproxy` binary in `-cmd` (headless) mode, which spiders
    and active-scans a target URL, then reports the alerts found.
    """

    name = "zap_cli"
    description = (
        "OWASP ZAP active scanner that spiders a target and tests it "
        "for common web vulnerabilities (XSS, SQLi, misconfigurations)."
    )
    params = {
        "target": "Full URL of the target, e.g. http://192.168.1.1",
    }

    def _validate(self, **kwargs: Any) -> None:
        """Validate that target is present and non-empty.

        Args:
            **kwargs: Execution parameters.

        Raises:
            ValueError: If target is missing or empty.
        """
        if kwargs.get("target") is None or len(kwargs["target"]) == 0:
            raise ValueError("target is required and cannot be empty")

    def _execute(self, **kwargs: Any) -> tuple[str, str]:
        """Build and run the zaproxy quick-scan command, then parse the report.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If zaproxy fails to produce a scan report.
        """
        target: str = kwargs["target"]
        report_path = f"/tmp/ares_zap_{uuid.uuid4().hex}.json"

        # -cmd runs ZAP headless. -quickurl spiders and active-scans the
        # target, -quickout writes a structured report — the .json
        # extension selects JSON format instead of ZAP's default HTML.
        cmd = WSL_PREFIX + [
            "zaproxy",
            "-cmd",
            "-quickurl",
            target,
            "-quickout",
            report_path,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        report = subprocess.run(
            WSL_PREFIX + ["cat", report_path],
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr + report.stdout

        if result.returncode != 0 and report.returncode != 0:
            raise RuntimeError(
                f"zaproxy exited with code {result.returncode}: {result.stderr}"
            )

        summary = self._parse(report.stdout)
        return summary, raw_output

    def _parse(self, report_json: str) -> str:
        """Extract alerts from the ZAP JSON report.

        Args:
            report_json: Raw contents of the ZAP quick-scan JSON report.

        Returns:
            Compact summary of alerts grouped by risk level.
        """
        try:
            report = json.loads(report_json)
        except json.JSONDecodeError:
            return "No alerts found."

        findings: list[str] = []
        for site in report.get("site", []):
            for alert in site.get("alerts", []):
                risk = alert.get("riskdesc", "Unknown")
                name = alert.get("name", "Unknown")
                findings.append(f"[{risk}] {name}")

        if not findings:
            return "No alerts found."

        return "ZAP alerts:\n" + "\n".join(findings)
