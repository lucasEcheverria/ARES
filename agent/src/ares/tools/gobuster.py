import subprocess
from pathlib import Path
from typing import Any

from .base import WSL_PREFIX, BaseTool

# Bundled with the project so gobuster always has a working wordlist,
# regardless of what's installed on the host system.
DEFAULT_WORDLIST = Path(__file__).parent / "wordlists" / "common.txt"

DEFAULT_EXTENSIONS = "php,html,txt"


def _to_wsl_path(windows_path: Path) -> str:
    """Convert a local Windows path to its WSL /mnt mount-point equivalent.

    gobuster now runs inside WSL, so a bundled Windows path like
    C:\\...\\common.txt is unusable as-is — it must be addressed as
    /mnt/c/.../common.txt from inside the Linux environment.

    Args:
        windows_path: Absolute Windows path to convert.

    Returns:
        The equivalent path as seen from inside WSL.
    """
    resolved = windows_path.resolve()
    drive = resolved.drive.rstrip(":").lower()
    rest = "/".join(resolved.parts[1:])
    return f"/mnt/{drive}/{rest}"


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
        "wordlist": (
            "Leave this empty. A working wordlist is bundled with the tool "
            "and used automatically. Only specify a path if you have a "
            "specific, verified wordlist file in mind."
        ),
        "extensions": (
            "File extensions to search (optional). Defaults to php,html,txt "
            "if not specified — leave empty unless you have a specific reason."
        ),
    }

    def _validate(self, **kwargs: Any) -> None:
        """Validate that target is present and non-empty.

        wordlist is intentionally not required here — it defaults to the
        bundled wordlist in _execute() if not provided.

        Args:
            **kwargs: Execution parameters.

        Raises:
            ValueError: If target is missing or empty.
        """
        if kwargs.get("target") is None or len(kwargs["target"]) == 0:
            raise ValueError("target is required and cannot be empty")

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
        # A custom wordlist is assumed to already be a valid path inside
        # WSL; only the bundled default (which lives on the Windows
        # filesystem) needs translating to its /mnt mount-point equivalent.
        wordlist: str = kwargs.get("wordlist") or _to_wsl_path(DEFAULT_WORDLIST)
        extensions: str = kwargs.get("extensions") or DEFAULT_EXTENSIONS

        # Build base command in dir mode.
        cmd = WSL_PREFIX + ["gobuster", "dir", "-u", target, "-w", wordlist]

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
            # Paths are printed without a leading slash in this version.
            if "(Status:" in line:
                findings.append(line.strip())

        if not findings:
            return "No paths discovered."

        return "Discovered paths:\n" + "\n".join(findings)
