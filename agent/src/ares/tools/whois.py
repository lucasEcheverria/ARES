import subprocess
from typing import Any

from .base import WSL_PREFIX, BaseTool

# Lines starting with any of these prefixes carry the registration
# details that matter for recon; the rest of whois output is legal
# boilerplate and registrar advertising.
_RELEVANT_PREFIXES = (
    "domain name:",
    "registrar:",
    "creation date:",
    "registry expiry date:",
    "updated date:",
    "name server:",
    "dnssec:",
    "registrant organization:",
    "registrant country:",
)


class WhoisTool(BaseTool):
    """Wrapper for whois domain registration lookup.

    Retrieves registration details for a domain: registrar, creation
    and expiry dates, name servers and registrant information.
    """

    name = "whois"
    description = (
        "Domain registration lookup that returns registrar, creation/"
        "expiry dates, name servers and registrant details."
    )
    params = {
        "domain": "Domain to look up, e.g. example.com",
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
        """Build and run the whois command, then parse the output.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If whois returns a non-zero exit code.
        """
        domain: str = kwargs["domain"]

        cmd = WSL_PREFIX + ["whois", domain]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        raw_output = result.stdout + result.stderr

        if result.returncode != 0:
            raise RuntimeError(
                f"whois exited with code {result.returncode}: {result.stderr}"
            )

        summary = self._parse(result.stdout, domain)
        return summary, raw_output

    def _parse(self, output: str, domain: str) -> str:
        """Extract registration fields from whois stdout.

        Args:
            output: Raw whois stdout.
            domain: The queried domain, used in the summary header.

        Returns:
            Compact summary of registrar, dates and name servers.
        """
        lines = output.splitlines()
        findings: list[str] = []

        for line in lines:
            if line.strip().lower().startswith(_RELEVANT_PREFIXES):
                findings.append(line.strip())

        if not findings:
            return f"No registration data found for {domain}."

        return f"WHOIS data for {domain}:\n" + "\n".join(findings)
