import subprocess
from typing import Any
from xml.etree import ElementTree

from .base import WSL_PREFIX, BaseTool

# zaproxy is installed as a snap package; its `zaproxy` shim on PATH tries
# to launch the GUI even under `wsl -e`, which has no display and always
# exits 1. Invoking the real binary directly with -cmd runs it headless.
ZAP_BINARY = "/snap/bin/zaproxy"

REPORT_PATH = "/tmp/zap_report.xml"


class ZapCliTool(BaseTool):
    """Wrapper for OWASP ZAP's headless command-line quick scan.

    Runs the ZAP binary directly in `-cmd` (headless) mode, which spiders
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
        """Build and run the ZAP quick-scan command, then parse the report.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).
        """
        target: str = kwargs["target"]

        # -cmd runs ZAP headless. -quickurl spiders and active-scans the
        # target, -quickout writes a structured XML report.
        cmd = WSL_PREFIX + [
            ZAP_BINARY,
            "-cmd",
            "-quickurl",
            target,
            "-quickout",
            REPORT_PATH,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        report = subprocess.run(
            WSL_PREFIX + ["cat", REPORT_PATH],
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr

        # ZAP's own exit code is unreliable in a headless WSL environment
        # (it may be non-zero even after a successful scan) — only the
        # presence of the report file tells us whether the scan produced
        # usable output.
        if report.returncode != 0 or not report.stdout.strip():
            fallback_summary = result.stdout.strip() or "No output captured."
            return fallback_summary, raw_output

        summary = self._parse(report.stdout)
        return summary, raw_output + report.stdout

    def _parse(self, report_xml: str) -> str:
        """Extract alerts from the ZAP XML report.

        Args:
            report_xml: Raw contents of the ZAP quick-scan XML report.

        Returns:
            Compact summary of alerts grouped by risk level.
        """
        try:
            root = ElementTree.fromstring(report_xml)
        except ElementTree.ParseError:
            return "No alerts found."

        findings: list[str] = []
        for alertitem in root.iter("alertitem"):
            name = alertitem.findtext("name", default="Unknown")
            riskdesc = alertitem.findtext("riskdesc", default="Unknown")
            findings.append(f"[{riskdesc}] {name}")

        if not findings:
            return "No alerts found."

        return "ZAP alerts:\n" + "\n".join(findings)
