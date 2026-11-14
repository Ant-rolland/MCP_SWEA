"""CLI entry point for STDIO and Streamable HTTP transports."""
from __future__ import annotations

import argparse

from swea_sentinel.config import load_settings


def main() -> None:
    settings = load_settings()
    parser = argparse.ArgumentParser(prog="swea-sentinel")
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="MCP transport (HTTP is local-only in P1)",
    )
    parser.add_argument(
        "--host", default=settings.server.transports.streamable_http.host
    )
    parser.add_argument(
        "--port", type=int, default=settings.server.transports.streamable_http.port
    )
    parser.add_argument("--db", default=settings.storage.path)
    args = parser.parse_args()

    if args.transport == "stdio" and not settings.server.transports.stdio.enabled:
        parser.error("STDIO transport is disabled by configuration.")
    if args.transport == "http":
        http = settings.server.transports.streamable_http
        if not http.enabled:
            parser.error("Streamable HTTP transport is disabled by configuration.")
        if args.host not in {"127.0.0.1", "localhost", "::1"}:
            parser.error("Remote binding is disabled in P1; HTTP is restricted to loopback.")

    from swea_sentinel.mcp.server import build_server

    server = build_server(args.db, settings=settings)
    if args.transport == "stdio":
        server.run(transport="stdio")
    else:
        server.settings.host = args.host
        server.settings.port = args.port
        server.run(transport="streamable-http")


if __name__ == "__main__":
    main()
