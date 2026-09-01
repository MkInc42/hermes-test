#!/usr/bin/env python3
"""
Meta Ads MCP stdio-to-HTTP bridge.

Reads JSON-RPC messages from stdin (newline-delimited), forwards them as HTTP
POST to the official Meta Ads MCP endpoint, handles SSE streaming responses,
and writes JSON-RPC results back to stdout.

This exists because:
1. Hermes' native HTTP MCP client (mcp.StreamableHTTP) fails during
   ClientSession.initialize() with MCPError(-32603) against Meta's server.
2. The mcp-remote npm bridge sends a malformed "meta" field that Meta rejects
   with: '"meta" for Request must be an dict or null.'

The raw HTTP path (verified working) bypasses both incompatibilities by
implementing just enough of Streamable HTTP to talk to Meta's server.
"""

import json
import os
import sys
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# Configuration — read token from env, never log or expose it
# ---------------------------------------------------------------------------

MCP_ENDPOINT = "https://mcp.facebook.com/ads"
ACCESS_TOKEN = os.environ.get("META_ADS_MCP_ACCESS_TOKEN", "")

if not ACCESS_TOKEN:
    # Fallback: try loading from the Hermes .env file directly.
    # This handles cases where ${...} interpolation in the config's
    # env section doesn't resolve at spawn time.
    env_paths = [
        os.path.expanduser("~/.hermes/.env"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
    ]
    for env_path in env_paths:
        if os.path.isfile(env_path):
            try:
                with open(env_path) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("META_ADS_MCP_ACCESS_TOKEN="):
                            ACCESS_TOKEN = line.split("=", 1)[1].strip("\"'")
                            break
            except OSError:
                pass
            if ACCESS_TOKEN:
                break

if not ACCESS_TOKEN:
    print(
        json.dumps({
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32000,
                "message": (
                    "META_ADS_MCP_ACCESS_TOKEN env var not set. "
                    "Check that the env section in config.yaml correctly "
                    "resolves ${META_ADS_MCP_ACCESS_TOKEN} from .env."
                ),
            },
        }),
        flush=True,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Session state — the Meta server issues a session ID on initialize,
# which must be sent as the "mcp-session-id" header on subsequent calls.
# ---------------------------------------------------------------------------

_session_id: str | None = None


def _build_headers() -> dict[str, str]:
    """Return HTTP headers for every MCP request to Meta."""
    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "meta-ads-mcp-bridge/1.0.0",
    }
    if _session_id:
        headers["mcp-session-id"] = _session_id
    return headers


def _sanitize_params(params: dict) -> dict:
    """Strip _meta from params — Meta rejects it even when it's a valid dict."""
    if "_meta" in params:
        params = dict(params)
        params.pop("_meta")
    return params


def _sanitize_request(request: dict) -> dict:
    """
    Ensure the JSON-RPC request's 'meta' field is a dict or null.
    Meta's server rejects requests where meta is any other type.
    This is a known incompatibility with some MCP clients (including
    Hermes' mcp test) that send meta as a non-dict value.
    """
    if "meta" in request:
        meta = request["meta"]
        if not isinstance(meta, dict) and meta is not None:
            request = dict(request)
            request["meta"] = None
    return request


def _send_http_post(body: bytes) -> str:
    """
    POST the JSON-RPC body to the Meta MCP endpoint and return the raw
    response body. Meta returns a text/event-stream even for single-shot
    JSON-RPC, so we read the whole response up to the first blank line
    (end of SSE event).
    """
    req = urllib.request.Request(
        MCP_ENDPOINT,
        data=body,
        headers=_build_headers(),
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        token_hint = ""
        if exc.code == 400:
            token_hint = (
                " (the Bearer token may be missing or invalid — "
                "check that META_ADS_MCP_ACCESS_TOKEN is resolved)"
            )
        raise RuntimeError(
            f"HTTP {exc.code}{token_hint}: {error_body[:500]}"
        ) from exc

    # Parse SSE: "data: <json>\n\n"
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("data: "):
            return line[len("data: "):]
        if line.startswith("data:"):
            return line[len("data:"):]

    # If no SSE data line found, return the raw body as-is
    return raw


def _handle_initialize(
    request_id: int | str,
    params: dict,
    meta: dict | None = None,
) -> str:
    """
    Send initialize and capture the session ID from the response headers
    (returned as "mcp-session-id"). Returns the JSON-RPC response string.
    """
    global _session_id

    body_dict = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": params,
    }
    if meta is not None:
        body_dict["meta"] = meta
    body = json.dumps(body_dict).encode("utf-8")

    req = urllib.request.Request(
        MCP_ENDPOINT,
        data=body,
        headers=_build_headers(),
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            # Capture session ID from response headers
            _session_id = resp.headers.get("mcp-session-id")
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        token_hint = ""
        if exc.code == 400:
            token_hint = (
                " (the Bearer token may be missing or invalid — "
                "check that META_ADS_MCP_ACCESS_TOKEN is resolved)"
            )
        raise RuntimeError(
            f"HTTP {exc.code}{token_hint}: {error_body[:500]}"
        ) from exc

    # Parse SSE data line
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("data: "):
            return line[len("data: "):]
        if line.startswith("data:"):
            return line[len("data:"):]
    return raw


# ---------------------------------------------------------------------------
# Main loop — read JSON-RPC lines from stdin, POST to Meta, write responses
# ---------------------------------------------------------------------------

def main() -> None:
    """Read JSON-RPC 2.0 messages from stdin and dispatch them to Meta."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            print(
                json.dumps({
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": f"Parse error: {exc}",
                    },
                }),
                flush=True,
            )
            continue

        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params", {})

        try:
            if method == "initialize":
                # Sanitize meta fields that Meta rejects
                meta = request.get("meta")
                if meta is not None and not isinstance(meta, dict):
                    meta = None
                params = _sanitize_params(params)
                response_str = _handle_initialize(req_id, params, meta)
            elif method == "notifications/initialized":
                # Meta doesn't require a response to initialized
                continue
            else:
                request = _sanitize_request(request)
                # Also sanitize _meta inside params
                if "params" in request and isinstance(request["params"], dict) and "_meta" in request["params"]:
                    request = dict(request)
                    request["params"] = _sanitize_params(request["params"])
                body = json.dumps(request).encode("utf-8")
                response_str = _send_http_post(body)

            # Parse the response to ensure it's valid JSON, then write it
            try:
                response = json.loads(response_str)
            except json.JSONDecodeError:
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": response_str,
                }

            print(json.dumps(response), flush=True)

        except RuntimeError as exc:
            # Log the sanitized request for debugging
            method_name = request.get("method", "unknown")
            req_id = request.get("id")
            debug_info = {
                "error": str(exc),
                "method": method_name,
            }
            # Only log the request body and meta for non-initialize requests
            # (initialize already logged separately)
            error_response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32603,
                    "message": str(exc),
                },
            }
            print(json.dumps(error_response), flush=True)
        except urllib.error.URLError as exc:
            error_response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32000,
                    "message": f"HTTP request failed: {exc.reason}",
                },
            }
            print(json.dumps(error_response), flush=True)


if __name__ == "__main__":
    main()