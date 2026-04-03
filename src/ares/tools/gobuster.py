import subprocess
from typing import Any

from .base import BaseTool


class GobusterTool(BaseTool):
    """Wrapper for gobuster directory and file brute-forcer.

    Runs gobuster in dir mode to discover hidden paths on a web server
    by testing each entry in a wordlist against the target URL.
    """

    name = "gobuster"
    description = (
        "Directory and file brute-forcer that discovers hidden paths "
        "on a web server using a wordlist."
    )
    params = {
        "target": "Full URL of the target, e.g. http://192.168.1.1",
        "wordlist": "Absolute path to the wordlist file",
        "extensions": "File extensions to search, e.g. php,html (optional)",
    }

    def _validate(self, **kwargs: Any) -> None:
        """Validate that target and wordlist are present and non-empty.

        Args:
            **kwargs: Execution parameters.

        Raises:
            ValueError: If target or wordlist are missing or empty.
        """
        if kwargs.get("target") is None or len(kwargs["target"]) == 0:
            raise ValueError("target is required and cannot be empty")
        if kwargs.get("wordlist") is None or len(kwargs["wordlist"]) == 0:
            raise ValueError("wordlist is required and cannot be empty")

    def _execute(self, **kwargs: Any) -> tuple[str, str]:
        """Build and run the gobuster command, then parse the output.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If gobuster returns a non-zero exit code.
        """
        target: str = kwargs["target"]
        wordlist: str = kwargs["wordlist"]
        extensions: str | None = kwargs.get("extensions")

        # Build base command in dir mode.
        cmd = ["gobuster", "dir", "-u", target, "-w", wordlist]

        # Append extensions if provided — gobuster accepts comma-separated values.
        if extensions:
            cmd += ["-x", extensions]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr

        if result.returncode != 0:
            raise RuntimeError(
                f"gobuster exited with code {result.returncode}: {result.stderr}"
            )

        summary = self._parse(result.stdout)
        return summary, raw_output

    def _parse(self, output: str) -> str:
        """Extract discovered paths from gobuster stdout.

        Args:
            output: Raw gobuster stdout.

        Returns:
            Compact summary of discovered paths and their status codes.
        """
        lines = output.splitlines()
        findings: list[str] = []

        for line in lines:
            # Gobuster marks found paths with their HTTP status code in brackets.
            if line.startswith("/") and "(Status:" in line:
                findings.append(line.strip())

        if not findings:
            return "No paths discovered."

        return "Discovered paths:\n" + "\n".join(findings)
