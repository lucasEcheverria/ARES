import subprocess
from typing import Any

from .base import WSL_PREFIX, BaseTool


class NucleiTool(BaseTool):
    """Wrapper for nuclei template-based vulnerability scanner.

    Runs nuclei's community templates against a target to detect known
    CVEs, misconfigurations and exposed panels.
    """

    name = "nuclei"
    description = (
        "Template-based vulnerability scanner that checks a target "
        "against known CVEs, misconfigurations and exposed panels."
    )
    params = {
        "target": "Full URL or host to scan, e.g. http://192.168.1.1",
        "severity": (
            "Comma-separated severities to filter by, e.g. medium,high,critical "
            "(optional, defaults to all severities)"
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
        """Build and run the nuclei command, then parse the output.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If nuclei returns a non-zero exit code.
        """
        target: str = kwargs["target"]
        severity: str | None = kwargs.get("severity")

        # -silent strips nuclei's banner and progress bar, leaving one
        # finding per line.
        cmd = WSL_PREFIX + ["nuclei", "-u", target, "-silent"]

        if severity:
            cmd += ["-severity", severity]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr

        if result.returncode != 0:
            raise RuntimeError(
                f"nuclei exited with code {result.returncode}: {result.stderr}"
            )

        summary = self._parse(result.stdout, target)
        return summary, raw_output

    def _parse(self, output: str, target: str) -> str:
        """Extract finding lines from nuclei stdout.

        Args:
            output: Raw nuclei stdout.
            target: The scanned target, used in the summary header.

        Returns:
            Compact summary of matched templates.
        """
        findings = [line.strip() for line in output.splitlines() if line.strip()]

        if not findings:
            return f"No issues found on {target}."

        return f"Nuclei findings for {target}:\n" + "\n".join(findings)
