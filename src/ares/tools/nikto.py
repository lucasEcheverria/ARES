import subprocess
from typing import Any

from .base import BaseTool


class NiktoTool(BaseTool):
    """Wrapper for nikto web server vulnerability scanner.

    Scans a web server for known vulnerabilities, misconfigurations,
    and exposed sensitive files using nikto's built-in test database.
    """

    name = "nikto"
    description = (
        "Web server scanner that detects known vulnerabilities, "
        "misconfigurations and exposed sensitive files."
    )
    params = {
        "target": "Full URL of the target, e.g. http://192.168.1.1",
        "port": "Target port (optional, defaults to 80)",
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
        """Build and run the nikto command, then parse the output.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If nikto returns a non-zero exit code.
        """
        target: str = kwargs["target"]
        port: str | None = kwargs.get("port")

        cmd = ["nikto", "-h", target]

        if port:
            cmd += ["-p", port]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr

        if result.returncode != 0:
            raise RuntimeError(
                f"nikto exited with code {result.returncode}: {result.stderr}"
            )

        summary = self._parse(result.stdout)
        return summary, raw_output

    def _parse(self, output: str) -> str:
        """Extract findings from nikto stdout.

        Args:
            output: Raw nikto stdout.

        Returns:
            Compact summary of detected vulnerabilities and issues.
        """
        lines = output.splitlines()
        findings: list[str] = []

        for line in lines:
            # Nikto prefixes findings with "+ "
            if line.startswith("+ ") and "Server" not in line:
                findings.append(line.strip())

        if not findings:
            return "No vulnerabilities or misconfigurations found."

        return "Nikto findings:\n" + "\n".join(findings)
