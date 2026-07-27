import subprocess
from typing import Any

from .base import WSL_PREFIX, BaseTool


class SubfinderTool(BaseTool):
    """Wrapper for subfinder passive subdomain discovery tool.

    Enumerates subdomains of a target domain using public sources,
    without sending any direct traffic to the target itself.
    """

    name = "subfinder"
    description = (
        "Passive subdomain enumeration tool that discovers subdomains "
        "of a target domain using public sources."
    )
    params = {
        "domain": "Root domain to enumerate, e.g. example.com",
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
        """Build and run the subfinder command, then parse the output.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If subfinder returns a non-zero exit code.
        """
        domain: str = kwargs["domain"]

        # -silent strips subfinder's banner and stats, leaving one
        # subdomain per line.
        cmd = WSL_PREFIX + ["/home/lucas/go/bin/nuclei", "-d", domain, "-silent"]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr

        if result.returncode != 0:
            raise RuntimeError(
                f"subfinder exited with code {result.returncode}: {result.stderr}"
            )

        summary = self._parse(result.stdout, domain)
        return summary, raw_output

    def _parse(self, output: str, domain: str) -> str:
        """Extract discovered subdomains from subfinder stdout.

        Args:
            output: Raw subfinder stdout.
            domain: The queried root domain, used in the summary header.

        Returns:
            Compact summary of discovered subdomains.
        """
        subdomains = [line.strip() for line in output.splitlines() if line.strip()]

        if not subdomains:
            return f"No subdomains found for {domain}."

        return f"Subdomains found for {domain}:\n" + "\n".join(subdomains)
