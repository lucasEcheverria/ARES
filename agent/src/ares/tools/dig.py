import subprocess
from typing import Any

from .base import WSL_PREFIX, BaseTool

DEFAULT_RECORD_TYPE = "A"


class DigTool(BaseTool):
    """Wrapper for dig DNS lookup utility.

    Queries DNS records for a domain — A, MX, TXT, NS, etc — to map
    out a target's DNS infrastructure.
    """

    name = "dig"
    description = (
        "DNS lookup tool that queries records (A, MX, TXT, NS, etc) "
        "for a domain."
    )
    params = {
        "domain": "Domain to query, e.g. example.com",
        "record_type": (
            "DNS record type to query, e.g. A, MX, TXT, NS, SOA "
            "(optional, defaults to A)"
        ),
    }

    def _validate(self, **kwargs: Any) -> None:
        """Validate that domain is present and non-empty.

        Args:
            **kwargs: Execution parameters.

        Raises:
            ValueError: If domain is missing or empty.
        """
        if kwargs.get("domain") is None or len(kwargs["domain"]) == 0:
            raise ValueError("domain is required and cannot be empty")

    def _execute(self, **kwargs: Any) -> tuple[str, str]:
        """Build and run the dig command, then parse the output.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If dig returns a non-zero exit code.
        """
        domain: str = kwargs["domain"]
        record_type: str = (kwargs.get("record_type") or DEFAULT_RECORD_TYPE).upper()

        # +noall +answer trims dig's verbose output down to the answer section.
        cmd = WSL_PREFIX + ["dig", "+noall", "+answer", domain, record_type]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr

        if result.returncode != 0:
            raise RuntimeError(
                f"dig exited with code {result.returncode}: {result.stderr}"
            )

        summary = self._parse(result.stdout, domain, record_type)
        return summary, raw_output

    def _parse(self, output: str, domain: str, record_type: str) -> str:
        """Extract the answer section from dig stdout.

        Args:
            output: Raw dig stdout.
            domain: The queried domain, used in the summary header.
            record_type: The queried record type, used in the summary header.

        Returns:
            Compact summary of the returned DNS records.
        """
        lines = [line.strip() for line in output.splitlines() if line.strip()]

        if not lines:
            return f"No {record_type} records found for {domain}."

        return f"{record_type} records for {domain}:\n" + "\n".join(lines)
