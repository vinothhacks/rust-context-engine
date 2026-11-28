"""Exercise the CLI and stdio MCP entry points of a built context-engine binary."""

import argparse
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


MCP_PROTOCOL = "2025-06-18"
PYTHON = "python" if os.name == "nt" else "python3"
MCP_TOOLS = {
    "context_doctor",
    "context_get",
    "context_index",
    "context_resume",
    "context_run",
    "context_search",
    "context_stats",
}
TIMEOUT = 60


def cli(binary, workspace, *args):
    result = subprocess.run(
        [str(binary), *args],
        cwd=workspace,
        capture_output=True,
        timeout=TIMEOUT,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{args[0]} exited {result.returncode}: "
            f"{result.stderr.decode('utf-8', errors='replace')}"
        )
    return result.stdout


async def verify_mcp(binary, workspace, version):
    with tempfile.TemporaryFile() as stderr:
        process = await asyncio.create_subprocess_exec(
            str(binary), "mcp", "--workspace", str(workspace),
            cwd=workspace,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=stderr,
        )

        async def send(method, request_id=None, params=None):
            message = {"jsonrpc": "2.0", "method": method}
            if request_id is not None:
                message["id"] = request_id
            if params is not None:
                message["params"] = params
            process.stdin.write(json.dumps(message).encode("utf-8") + b"\n")
            await process.stdin.drain()

        async def receive(request_id):
            raw = await asyncio.wait_for(process.stdout.readline(), TIMEOUT)
            assert raw, f"MCP closed stdout before responding to request {request_id}"
            message = json.loads(raw)
            assert message["jsonrpc"] == "2.0", message
            assert message["id"] == request_id, message
            assert "error" not in message, message
            return message["result"]

        try:
            await send("initialize", 1, {
                "protocolVersion": MCP_PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "verify-binary", "version": "1"},
            })
            initialized = await receive(1)
            assert initialized["protocolVersion"] == MCP_PROTOCOL, initialized
            assert initialized["serverInfo"] == {
                "name": "context-engine", "version": version,
            }, initialized
            assert "tools" in initialized["capabilities"], initialized

            await send("notifications/initialized")
            await send("tools/list", 2)
            tools = [tool["name"] for tool in (await receive(2))["tools"]]
            assert sorted(tools) == sorted(MCP_TOOLS), tools

            process.stdin.close()
            trailing_stdout = await asyncio.wait_for(process.stdout.read(), TIMEOUT)
            assert trailing_stdout == b"", trailing_stdout
            status = await asyncio.wait_for(process.wait(), TIMEOUT)
            if status != 0:
                stderr.seek(0)
                raise RuntimeError(f"MCP exited {status}: {stderr.read()!r}")
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    print(f"MCP {MCP_PROTOCOL}, context-engine {version}, clean exit on stdin EOF")
    print(f"Tools: {', '.join(sorted(tools))}")


def verify_recovery(binary, workspace):
    fixtures = {
        "utf8": ("café 日本語\n".encode(), "résumé λ\n".encode()),
        "crlf": (b"first\r\nsecond\r\n", b"warning\r\nlast\r\n"),
        "ansi": (b"\x1b[32mpass\x1b[0m\n", b"\x1b[31mwarning\x1b[0m\n"),
        "binary": (b"\x00\xff\xc3\x28\x1a\r\n", b"\x80\x00\xfe\x1a"),
        "large": (
            "INFO sample record café\r\n".encode() * 24_000,
            b"\x1b[33mWARN sample record\x1b[0m\r\n" * 12_000,
        ),
    }
    emit = (
        "import sys; from pathlib import Path; "
        "sys.stdout.buffer.write(Path('stdout.bin').read_bytes()); "
        "sys.stderr.buffer.write(Path('stderr.bin').read_bytes())"
    )
    for name, (stdout, stderr) in fixtures.items():
        (workspace / "stdout.bin").write_bytes(stdout)
        (workspace / "stderr.bin").write_bytes(stderr)
        envelope = json.loads(cli(
            binary, workspace, "run", "--workspace", str(workspace), "--json",
            "--", PYTHON, "-c", emit,
        ))
        capture = envelope["capture"]
        assert capture["complete"] and capture["originals_available"], name
        assert envelope["view"]["transformations"], name
        artifact_id = envelope["artifact_id"]

        for stream, original in (("stdout", stdout), ("stderr", stderr)):
            digest = hashlib.sha256(original).hexdigest()
            assert capture[f"{stream}_sha256"] == digest, (name, stream)
            assert capture[f"{stream}_bytes"] == len(original), (name, stream)
            recovered = bytearray()
            page_size = envelope["recovery"]["max_bytes_per_call"]
            for start in range(0, len(original), page_size):
                end = min(start + page_size, len(original))
                page = json.loads(cli(
                    binary, workspace, "get", artifact_id, "--stream", stream,
                    "--bytes", f"{start}:{end}", "--workspace", str(workspace), "--json",
                ))
                assert page["mode"] == "bytes" and page["exact_raw_preserved"], (name, stream)
                assert page["artifact_id"] == artifact_id and page["stream"] == stream
                assert page["returned_range"] == {"start": start, "end": end}, page["returned_range"]
                assert page["has_more"] == (end < len(original))
                assert page["total_bytes"] == len(original) and page["sha256"] == digest
                decoded = base64.b64decode(page["base64_bytes"], validate=True)
                assert page["byte_length"] == len(decoded) == end - start
                recovered.extend(decoded)

            assert recovered == original, (name, stream, "recovered bytes")
            assert hashlib.sha256(recovered).hexdigest() == digest, (name, stream, "hash")
            if name == "large":
                blob = workspace / ".context-engine" / "store" / "blobs" / digest[:2] / f"{digest}.zst"
                assert 0 < blob.stat().st_size < len(original), (name, stream, "zstd size")
            print(f"Recovery {name}/{stream}: {len(original)} bytes, SHA-256 {digest}")

        if name == "large":
            assert len(envelope["view"]["safe_excerpt"].encode()) < len(stdout) + len(stderr)


def main():
    if not __debug__:
        raise SystemExit("Run the smoke test with Python assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    options = parser.parse_args()
    binary = options.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="context-engine-smoke-") as directory:
        workspace = Path(directory)
        version_line = cli(binary, workspace, "--version").decode("utf-8").strip()
        name, version = version_line.split()
        assert name == "context-engine" and version, version_line
        print(version_line, flush=True)
        asyncio.run(verify_mcp(binary, workspace, version))
        verify_recovery(binary, workspace)


if __name__ == "__main__":
    main()
