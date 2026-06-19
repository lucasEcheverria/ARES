import argparse

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
        help="IP address or hostname of the target to scan.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=50,
        help="Maximum number of ReAct loop iterations (default: 50).",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for the ARES CLI.

    Initializes a TargetState from CLI arguments, runs the agent's
    full ReAct loop, and prints the resulting report to stdout.
    """
    args = _parse_args()

    state = TargetState(
        raw_prompt=f"Perform reconnaissance on {args.target}",
        target=args.target,
        target_context=None,
        current_phase=Phase.RECON,
        global_checklist=[],
        phase_checklist=[],
        confirmed=[],
        raw=[],
    )

    agent = Agent()
    agent.MAX_ITERATIONS = args.max_iterations

    report = agent.run(state)

    print("\n" + "=" * 60)
    print(report)


if __name__ == "__main__":
    main()
