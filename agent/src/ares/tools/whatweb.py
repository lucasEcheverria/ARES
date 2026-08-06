import subprocess
from typing import Any

from .base import WSL_PREFIX, BaseTool


class WhatwebTool(BaseTool):
    """Wrapper for WhatWeb web technology fingerprinting tool.

    Identifies the technologies powering a target website: CMS, web
    server, JavaScript libraries, frameworks and other plugins.
    """

    name = "whatweb"
    description = (
        "Web technology fingerprinting tool that identifies the CMS, "
        "server software, frameworks and libraries running on a target."
    )
    params = {
        "target": "Full URL or host to fingerprint, e.g. http://192.168.1.1",
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
        """Build and run the whatweb command, then parse the output.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If whatweb returns a non-zero exit code.
        """
        target: str = kwargs["target"]

        # --color=never keeps the single-line report free of ANSI codes.
        cmd = WSL_PREFIX + ["whatweb", "--color=never", target]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr

        if result.returncode != 0:
            raise RuntimeError(
                f"whatweb exited with code {result.returncode}: {result.stderr}"
            )

        summary = self._parse(result.stdout)
        return summary, raw_output

    def _parse(self, output: str) -> str:
        """Extract the fingerprint report from whatweb stdout.

        Args:
            output: Raw whatweb stdout.

        Returns:
            Compact summary of identified technologies.
        """
        lines = [line.strip() for line in output.splitlines() if line.strip()]

        if not lines:
            return "No technologies identified."

        return "WhatWeb fingerprint:\n" + "\n".join(lines)
