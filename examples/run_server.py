#!/usr/bin/env python3
"""Launch the ACES web interface.

Opens a browser to the dashboard where you can configure and run
simulations with live progress tracking.

Usage:
    python examples/run_server.py
    python examples/run_server.py --port 8150
"""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aces.web.server import run_server


def main() -> None:
    parser = argparse.ArgumentParser(description="ACES — Web Dashboard Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=8150, help="Port (default: 8150)")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open browser")
    args = parser.parse_args()

    if not args.no_browser:
        webbrowser.open(f"http://{args.host}:{args.port}")

    run_server(args.host, args.port)


if __name__ == "__main__":
    main()
