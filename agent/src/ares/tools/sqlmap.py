import subprocess
from typing import Any

from .base import WSL_PREFIX, BaseTool

# Lines carrying these prefixes describe a confirmed injection point;
# the rest of sqlmap's output is progress noise and HTTP request logs.
_FINDING_PREFIXES = ("Parameter:", "Type:", "Title:", "Payload:")


class SqlmapTool(BaseTool):
    """Wrapper for sqlmap SQL injection detection tool.

    Probes a target URL's parameters (or POST body) for SQL injection
    vulnerabilities and reports the injection point and technique used.
    """

    name = "sqlmap"
    description = (
        "SQL injection scanner that tests URL parameters for injectable "
        "points and reports the vulnerable parameter and technique."
    )
    params = {
        "url": "Full URL with parameters to test, e.g. http://192.168.1.1/item?id=1",
        "data": "POST body to test instead of URL parameters (optional)",
        "cookie": (
            "Cookie header to authenticate the request, e.g. PHPSESSID=abc "
            "(optional)"
        ),
    }

    def _validate(self, **kwargs: Any) -> None:
        """Validate that url is present and non-empty.

        Args:
            **kwargs: Execution parameters.

        Raises:
            ValueError: If url is missing or empty.
        """
        if kwargs.get("url") is None or len(kwargs["url"]) == 0:
            raise ValueError("url is required and cannot be empty")

    def _execute(self, **kwargs: Any) -> tuple[str, str]:
        """Build and run the sqlmap command, then parse the output.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If sqlmap returns a non-zero exit code.
        """
        url: str = kwargs["url"]
        data: str | None = kwargs.get("data")
        cookie: str | None = kwargs.get("cookie")

        # --batch accepts sqlmap's default answer on every prompt so the
        # scan never blocks waiting for interactive input.
        cmd = WSL_PREFIX + ["sqlmap", "-u", url, "--batch"]

        if data:
            cmd += ["--data", data]

        if cookie:
            cmd += ["--cookie", cookie]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr

        if result.returncode != 0:
            raise RuntimeError(
                f"sqlmap exited with code {result.returncode}: {result.stderr}"
            )

        summary = self._parse(result.stdout, url)
        return summary, raw_output

    def _parse(self, output: str, url: str) -> str:
        """Extract confirmed injection points from sqlmap stdout.

        Args:
            output: Raw sqlmap stdout.
            url: The tested URL, used in the summary header.

        Returns:
            Compact summary of injectable parameters and techniques.
        """
        lines = output.splitlines()
        findings: list[str] = []

        for line in lines:
            stripped = line.strip()
            if stripped.startswith(_FINDING_PREFIXES):
                findings.append(stripped)

        if not findings:
            return f"No injectable parameters found on {url}."

        return f"sqlmap findings for {url}:\n" + "\n".join(findings)
