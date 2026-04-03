import subprocess
from typing import Any

from .base import BaseTool

# Maps each mode to its nmap flags.
# Kept at module level to avoid rebuilding the dict on every call.
SCAN_MODES: dict[str, list[str]] = {
    "quick": ["-T4", "-F"],
    "services": ["-T4", "-sV", "-p-"],
    "scripts": ["-T4", "-sV", "-sC", "-p-"],
}


class NmapTool(BaseTool):
    """Wrapper for nmap network scanner.

    Supports three scan modes with increasing depth: quick port discovery,
    service version detection, and NSE script-based reconnaissance.
    """

    name = "nmap"
    description = (
        "Network scanner that discovers open ports, running services "
        "and their versions on a target host."
    )
    params = {
        "target": "IP or hostname to scan",
        "mode": "quick | services | scripts",
        "ports": "specific ports, e.g. 80,443 (optional, overrides mode defaults)",
    }

    def _validate(self, **kwargs: Any) -> None:
        """Validate that target and mode are present and correct.

        Args:
            **kwargs: Execution parameters.

        Raises:
            ValueError: If target is missing or mode is not valid.
        """
        if kwargs.get("target") is None or len(kwargs["target"]) == 0:
            raise ValueError("target is required and cannot be empty")
        if kwargs.get("mode") not in SCAN_MODES:
            raise ValueError("mode must be one of: quick, services, scripts")

    def _execute(self, **kwargs: Any) -> tuple[str, str]:
        """Build and run the nmap command, then parse the output.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If nmap returns a non-zero exit code.
        """
        target: str = kwargs["target"]
        mode: str = kwargs["mode"]
        ports: str | None = kwargs.get("ports")

        # Build command from mode flags, injecting custom ports if provided.
        cmd = ["nmap"] + SCAN_MODES[mode]
        if ports:
            cmd += ["-p", ports]
        cmd.append(target)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr

        if result.returncode != 0:
            raise RuntimeError(
                f"nmap exited with code {result.returncode}: {result.stderr}"
            )

        summary = self._parse(result.stdout)
        return summary, raw_output

    def _parse(self, output: str) -> str:
        """Extract open ports and services from nmap stdout.

        Args:
            output: Raw nmap stdout.

        Returns:
            Compact summary of open ports and detected services.
        """
        lines = output.splitlines()
        findings: list[str] = []

        for line in lines:
            # nmap marks open ports with "open" in the state column
            if "open" in line and "/tcp" in line or "/udp" in line:
                findings.append(line.strip())

        if not findings:
            return "No open ports found."

        return f"Open ports on {output.split()[0]}:\n" + "\n".join(findings)
