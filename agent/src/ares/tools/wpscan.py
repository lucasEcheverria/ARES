import subprocess
from typing import Any

from .base import WSL_PREFIX, BaseTool


class WpscanTool(BaseTool):
    """Wrapper for WPScan WordPress vulnerability scanner.

    Enumerates a WordPress target's core version, plugins and themes,
    and cross-references them against known vulnerabilities.
    """

    name = "wpscan"
    description = (
        "WordPress-specific scanner that identifies the core version, "
        "plugins and themes in use and flags known vulnerabilities."
    )
    params = {
        "target": "Full URL of the WordPress site, e.g. http://192.168.1.1",
        "api_token": (
            "WPScan API token to enrich results with vulnerability data "
            "(optional, scan runs without it but with fewer details)"
        ),
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
        """Build and run the wpscan command, then parse the output.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If wpscan fails to produce a scan report.
        """
        target: str = kwargs["target"]
        api_token: str | None = kwargs.get("api_token")

        # --no-update skips wpscan's vulnerability-database update check,
        # so the scan doesn't stall waiting on a network call before it starts.
        cmd = WSL_PREFIX + [
            "wpscan",
            "--url",
            target,
            "--no-banner",
            "--random-user-agent",
            "--no-update",
        ]

        if api_token:
            cmd += ["--api-token", api_token]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr

        # WPScan uses dedicated non-zero exit codes to signal that
        # vulnerable software was identified — that's a scan result, not
        # a failure, so only a report with no usable output counts as an error.
        if result.returncode != 0 and not result.stdout.strip():
            raise RuntimeError(
                f"wpscan exited with code {result.returncode}: {result.stderr}"
            )

        summary = self._parse(result.stdout)
        return summary, raw_output

    def _parse(self, output: str) -> str:
        """Extract finding and warning lines from wpscan stdout.

        Args:
            output: Raw wpscan stdout.

        Returns:
            Compact summary of identified components and vulnerabilities.
        """
        lines = output.splitlines()
        findings: list[str] = []

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[+]") or stripped.startswith("[!]"):
                findings.append(stripped)

        if not findings:
            return "No WordPress findings detected."

        return "WPScan findings:\n" + "\n".join(findings)
