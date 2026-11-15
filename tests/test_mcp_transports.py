"""End-to-end MCP transport smoke tests using the official SDK client."""
from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

try:
    from mcp.client.streamable_http import streamable_http_client
except ImportError:  # Compatibility with earlier v1 SDK releases.
    from mcp.client.streamable_http import streamablehttp_client as streamable_http_client


EXPECTED_TOOLS = {
    "swea_initialize_project",
    "swea_analyze_project",
    "swea_analyze_architecture",
    "swea_analyze_contracts",
    "swea_analyze_dependencies",
    "swea_check_blast_radius",
    "swea_get_project_context",
    "swea_get_project_status",
    "swea_refresh_project_index",
}


def test_stdio_transport_initializes_and_lists_tools(tmp_path):
    async def run_client() -> set[str]:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m", "swea_sentinel", "--transport", "stdio",
                "--db", str(tmp_path / "stdio.sqlite"),
            ],
            cwd=str(Path.cwd()),
        )
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.list_tools()
                return {tool.name for tool in result.tools}

    assert asyncio.run(run_client()) == EXPECTED_TOOLS


def test_streamable_http_transport_initializes_and_lists_tools(tmp_path):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    process = subprocess.Popen(
        [
            sys.executable, "-m", "swea_sentinel", "--transport", "http",
            "--host", "127.0.0.1", "--port", str(port),
            "--db", str(tmp_path / "http.sqlite"),
        ],
        cwd=str(Path.cwd()),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    async def run_client() -> set[str]:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("SWEA Sentinel HTTP server exited before accepting connections")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                await asyncio.sleep(0.1)
        else:
            raise TimeoutError("SWEA Sentinel HTTP server did not start within 25 seconds")

        async with streamable_http_client(f"http://127.0.0.1:{port}/mcp") as streams:
            read_stream, write_stream = streams[:2]
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.list_tools()
                return {tool.name for tool in result.tools}

    try:
        assert asyncio.run(run_client()) == EXPECTED_TOOLS
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
