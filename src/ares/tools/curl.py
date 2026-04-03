import subprocess
from typing import Any

from .base import BaseTool


class CurlTool(BaseTool):
    """Wrapper for curl HTTP client.

    Sends HTTP requests to a target URL and returns the response
    status, headers and body for the agent to reason about.
    """

    name = "curl"
    description = (
        "HTTP client that sends requests to a URL and returns the "
        "response status code, headers and body."
    )
    params = {
        "url": "Full URL to request, e.g. http://192.168.1.1/login",
        "method": "HTTP method: GET, POST, PUT, DELETE (optional, defaults to GET)",
        "data": "Request body for POST/PUT requests (optional)",
        "headers": "Additional headers as key:value pairs, e.g. key:value (optional)",
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
        """Build and run the curl command, then parse the output.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If curl returns a non-zero exit code.
        """
        url: str = kwargs["url"]
        method: str = kwargs.get("method", "GET").upper()
        data: str | None = kwargs.get("data")
        headers: str | None = kwargs.get("headers")

        # -s silences progress bar, -i includes response headers in output.
        cmd = ["curl", "-s", "-i", "-X", method]

        if headers:
            cmd += ["-H", headers]

        if data:
            cmd += ["-d", data]

        cmd.append(url)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr

        if result.returncode != 0:
            raise RuntimeError(
                f"curl exited with code {result.returncode}: {result.stderr}"
            )

        summary = self._parse(result.stdout)
        return summary, raw_output

    def _parse(self, output: str) -> str:
        """Extract status code, relevant headers and body preview from curl output.

        Args:
            output: Raw curl stdout including headers and body.

        Returns:
            Compact summary with status code and response preview.
        """
        lines = output.splitlines()
        status_line = ""
        body_start = 0

        for i, line in enumerate(lines):
            # The first line of curl output with -i is the HTTP status line.
            if line.startswith("HTTP/"):
                status_line = line.strip()
            # Headers and body are separated by a blank line.
            if line == "" and status_line:
                body_start = i + 1
                break

        body_preview = "\n".join(lines[body_start : body_start + 5]).strip()

        if not status_line:
            return "Could not parse curl response."

        return f"{status_line}\nBody preview:\n{body_preview}"
