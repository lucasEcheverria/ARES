import subprocess
from typing import Any

from .base import WSL_PREFIX, BaseTool

DEFAULT_PORT = "443"


class OpensslTool(BaseTool):
    """Wrapper for openssl s_client certificate inspection.

    Connects to a target host/port over TLS and retrieves the leaf
    certificate's subject, issuer and validity dates.
    """

    name = "openssl"
    description = (
        "TLS certificate inspector that connects to a host/port and "
        "returns the certificate subject, issuer and validity dates."
    )
    params = {
        "target": "Host to connect to, e.g. example.com",
        "port": "TLS port to connect to (optional, defaults to 443)",
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
        """Open a TLS handshake and pipe the certificate through x509, then parse it.

        Args:
            **kwargs: Validated execution parameters.

        Returns:
            Tuple of (summary, raw_output).

        Raises:
            RuntimeError: If the certificate cannot be parsed.
        """
        target: str = kwargs["target"]
        port: str = str(kwargs.get("port") or DEFAULT_PORT)

        # Feeding empty stdin makes s_client complete the handshake, print
        # the certificate, and exit instead of blocking on interactive
        # input. -servername enables SNI so name-based vhosts return the
        # right certificate. A timeout guards against unresponsive hosts.
        handshake = subprocess.run(
            WSL_PREFIX
            + [
                "openssl",
                "s_client",
                "-connect",
                f"{target}:{port}",
                "-servername",
                target,
            ],
            input="",
            capture_output=True,
            text=True,
            timeout=15,
        )

        cert = subprocess.run(
            WSL_PREFIX + ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates"],
            input=handshake.stdout,
            capture_output=True,
            text=True,
        )

        raw_output = handshake.stdout + handshake.stderr + cert.stdout + cert.stderr

        # The handshake step (s_client) can return non-zero on some servers
        # even when it printed a usable certificate, so only the x509
        # parsing step's exit code determines success here.
        if cert.returncode != 0:
            raise RuntimeError(
                f"openssl could not parse a certificate for {target}: {cert.stderr}"
            )

        summary = self._parse(cert.stdout, target)
        return summary, raw_output

    def _parse(self, output: str, target: str) -> str:
        """Extract certificate fields from openssl x509 stdout.

        Args:
            output: Raw openssl x509 stdout.
            target: The connected host, used in the summary header.

        Returns:
            Compact summary of the certificate's subject, issuer and dates.
        """
        lines = [line.strip() for line in output.splitlines() if line.strip()]

        if not lines:
            return f"Could not retrieve certificate for {target}."

        return f"Certificate details for {target}:\n" + "\n".join(lines)
