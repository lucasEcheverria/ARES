import argparse
from urllib.parse import urlparse

from .core.agent import Agent
from .core.memory import Phase, TargetState


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the ARES CLI.

    Returns:
        Parsed arguments with target and max_iterations.
    """
    parser = argparse.ArgumentParser(
        prog="ares",
        description="ARES — Autonomous Red-teaming & Exploitation System",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL, IP, or hostname, e.g. http://localhost:8080",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=50,
        help="Maximum number of ReAct loop iterations (default: 50).",
    )
    parser.add_argument(
        "--session-id",
        required=False,
        default=None,
        help="Session ID from the database, used when launched by the server.",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for the ARES CLI.

    Initializes a TargetState from CLI arguments, runs the agent's
    full ReAct loop, and prints the resulting report to stdout.
    """
    args = _parse_args()

    # nmap and similar tools expect a bare host/IP, not a full URL with
    # scheme and port. Split those out and keep them as context instead,
    # so the LLM still has the full picture without breaking tool calls.
    parsed = urlparse(args.target)
    host = parsed.hostname or args.target
    context_parts = []
    if parsed.scheme:
        context_parts.append(f"protocol: {parsed.scheme}")
    if parsed.port:
        context_parts.append(f"port: {parsed.port}")
    target_context = (
        f"Web service reachable at {args.target} ({', '.join(context_parts)})"
        if context_parts
        else None
    )

    state = TargetState(
        raw_prompt=f"Perform reconnaissance on {args.target}",
        target=host,
        target_context=target_context,
        current_phase=Phase.RECON,
        global_checklist=[],
        phase_checklist=[],
        confirmed=[],
        raw=[],
        session_id = args.session_id,
    )

    agent = Agent()
    agent.MAX_ITERATIONS = args.max_iterations

    report = agent.run(state)

    print("\n" + "=" * 60)
    print(report)


if __name__ == "__main__":
    main()
