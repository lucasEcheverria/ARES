import subprocess
from typing import Any

from .base import WSL_PREFIX, BaseTool


class TestsslTool(BaseTool):
    """Wrapper for testssl.sh TLS/SSL configuration scanner.

    Analyzes a target's TLS/SSL setup for supported protocols, cipher
    strength and known vulnerabilities (Heartbleed, POODLE, etc).
    """

    name = "testssl"
    description = (
        "TLS/SSL scanner that checks a target's certificate, supported "
        "protocols, ciphers and known vulnerabilities."
    )
    params = {
        "target": "Host and optional port to scan, e.g. example.com:443",
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
        """Build and run the testssl.sh command, then parse the output.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If testssl.sh returns a non-zero exit code.
        """
        target: str = kwargs["target"]

        # --quiet skips the banner, --color 0 disables ANSI codes so the
        # output can be parsed as plain text.
        cmd = WSL_PREFIX + ["testssl", "--quiet", "--color", "0", target]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr

        if result.returncode != 0:
            raise RuntimeError(
                f"testssl.sh exited with code {result.returncode}: {result.stderr}"
            )

        summary = self._parse(result.stdout)
        return summary, raw_output

    def _parse(self, output: str) -> str:
        """Extract flagged vulnerabilities from testssl.sh stdout.

        Args:
            output: Raw testssl.sh stdout.

        Returns:
            Compact summary of detected TLS/SSL vulnerabilities.
        """
        lines = output.splitlines()
        findings: list[str] = []

        for line in lines:
            # testssl.sh marks weaknesses with "VULNERABLE" in plain-text mode.
            if "VULNERABLE" in line:
                findings.append(line.strip())

        if not findings:
            return "No TLS/SSL vulnerabilities found."

        return "TLS/SSL findings:\n" + "\n".join(findings)
