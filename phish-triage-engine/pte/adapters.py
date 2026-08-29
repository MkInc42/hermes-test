"""Safe, passive enrichment source adapters.

Live adapters are opt-in.  The default worker uses no network and represents
unconfigured providers explicitly instead of treating missing coverage as a
clean reputation result.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from queue import Empty, Queue
from typing import Any

from .enrichment import source_result

AddressResolver = Callable[[str], list[tuple[Any, ...]]]


def _resolve_addresses(hostname: str) -> list[tuple[Any, ...]]:
    """Resolve addresses with the platform resolver; no ports are contacted."""
    return socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)


def dns_lookup(
    hostname: str,
    *,
    timeout_seconds: float = 2.0,
    resolver: AddressResolver = _resolve_addresses,
) -> dict[str, Any]:
    """Return a normalized passive DNS result without raising provider errors.

    A daemon worker provides a caller-side deadline around libc resolvers whose
    timeout cannot be configured portably.  A stalled OS resolver therefore
    cannot extend the deadline or block interpreter shutdown.  Tests inject a
    resolver, making timeout and error handling deterministic.
    """
    if not hostname.strip():
        return source_result(
            "dns", status="not_found", observable=hostname,
            limitations=["No hostname was available for DNS resolution."],
        )
    if timeout_seconds <= 0:
        return source_result(
            "dns", status="unavailable", observable=hostname,
            limitations=["DNS lookup deadline must be greater than zero."],
        )
    result_queue: Queue[tuple[bool, Any]] = Queue(maxsize=1)

    def resolve() -> None:
        try:
            result_queue.put((True, resolver(hostname)))
        except Exception as exc:
            result_queue.put((False, exc))

    thread = threading.Thread(target=resolve, name="pte-dns", daemon=True)
    thread.start()
    try:
        succeeded, value = result_queue.get(timeout=timeout_seconds)
    except Empty:
        return source_result(
            "dns", status="unavailable", observable=hostname,
            limitations=[f"DNS resolution exceeded the {timeout_seconds:g}s deadline."],
        )
    if not succeeded and isinstance(value, socket.gaierror):
        exc = value
        not_found_codes = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)}
        status = "not_found" if exc.errno in not_found_codes else "unavailable"
        return source_result(
            "dns", status=status, observable=hostname,
            limitations=[f"DNS resolver did not return an address ({exc.errno})."],
        )
    if not succeeded:
        exc = value
        return source_result(
            "dns", status="error", observable=hostname,
            limitations=[f"DNS resolver failed safely: {type(exc).__name__}."],
        )

    try:
        addresses = set()
        for item in value:
            if not isinstance(item, tuple) or len(item) < 5:
                raise ValueError("malformed resolver record")
            sockaddr = item[4]
            if (
                not isinstance(sockaddr, tuple)
                or not sockaddr
                or not isinstance(sockaddr[0], str)
                or not sockaddr[0]
            ):
                raise ValueError("malformed resolver address")
            addresses.add(sockaddr[0])
        addresses = sorted(addresses)
    except Exception:
        return source_result(
            "dns", status="error", observable=hostname,
            limitations=["DNS resolver returned malformed output."],
        )
    if not addresses:
        return source_result(
            "dns", status="not_found", observable=hostname,
            data={"addresses": []}, limitations=["Resolver returned no A or AAAA addresses."],
        )
    return source_result(
        "dns", status="ok", observable=hostname,
        provider="system-getaddrinfo", data={"addresses": addresses},
        limitations=["Passive A/AAAA resolution only; no service connection or active scan was performed."],
    )


def unavailable_provider_results(observable: str) -> dict[str, dict[str, Any]]:
    """Return normalized offline defaults for every tool-backed source slot."""
    reasons = {
        "urlhaus_abusech": "URLhaus adapter is disabled; no external reputation request was made.",
        "otx": "OTX adapter is disabled; no external reputation request was made.",
        "google_safe_browsing": "Google Safe Browsing adapter is disabled; no API key was used.",
        "rdap_whois": "RDAP/WHOIS adapter is disabled in safe local mode.",
        "domain_age": "Domain age requires an RDAP/WHOIS observation.",
        "asn_hosting": "ASN/hosting lookup is disabled in safe local mode.",
        "tls_certificate_transparency": "TLS/certificate-transparency lookup is disabled in safe local mode.",
        "dns": "DNS is opt-in; pass --enable-dns to perform passive resolution.",
    }
    return {
        source: source_result(
            source, status="unavailable", observable=observable,
            limitations=[reason],
        )
        for source, reason in reasons.items()
    }
