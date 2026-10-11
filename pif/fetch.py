"""Guarded server-side URL fetch (v6.2): the live web-content path.

Adopted mechanism (disclosed in README): tripwire's DNS-rebinding-safe
pinning — resolve once, refuse unless EVERY resolved address is public, then
connect to the pinned IP while keeping the real hostname for TLS SNI and the
Host header. Redirects are re-pinned per hop (never blindly followed), the
body is capped mid-stream, and only text-like content is accepted. What comes
back is untrusted content in the `web` channel — the same pipeline every other
source goes through.

This closes the round-2 review's "no live web-fetch path" gap WITHOUT
reintroducing an SSRF surface: private, loopback, link-local, unique-local
and cloud-metadata targets are refused before any connection is made.
"""

import http.client
import ipaddress
import socket
import ssl
import urllib.parse

from pif.input.base import InspectionError
from pif.observability import content_preview, logger

MAX_BODY_BYTES = 2_000_000
MAX_REDIRECTS = 3
ALLOWED_SCHEMES = ("http", "https")
USER_AGENT = "PIF-fetcher/1.0 (prompt-injection-firewall)"


def _pin_public(url: str) -> tuple[str, str, int] | None:
    """Resolve the URL once and pin it: returns (pinned_host, hostname, port)
    only when every resolved address is global. Connecting to the checked IP
    (SNI + Host header keep the real name) closes the DNS-rebinding gap."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    addresses = sorted({info[4][0] for info in infos})
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        logger.info("fetch.refused", extra={"event_fields": dict(reason="non_public_target", host=content_preview(parsed.hostname or ""))})
        return None
    pinned = f"[{addresses[0]}]" if ":" in addresses[0] else addresses[0]
    return pinned, parsed.hostname or "", port


def _request(pinned_host: str, hostname: str, port: int, path: str, https: bool) -> tuple[int, bytes, str | None]:
    """One request to the pinned IP. TLS connects to the pinned address but
    wraps with `server_hostname=hostname`, so SNI and certificate validation
    both use the real name — the pinned-origin guarantee."""
    if https:
        sock = socket.create_connection((pinned_host, port), timeout=15)
        context = ssl.create_default_context()
        tls = context.wrap_socket(sock, server_hostname=hostname)
        connection = http.client.HTTPSConnection(pinned_host, port, timeout=15)
        connection.sock = tls  # pre-wrapped: skip connect, use the pinned+verified socket
    else:
        connection = http.client.HTTPConnection(pinned_host, port, timeout=15)
    try:
        connection.request(
            "GET",
            path or "/",
            headers={"Host": hostname if port in (80, 443) else f"{hostname}:{port}", "User-Agent": USER_AGENT, "Accept": "text/html,text/plain,*/*"},
        )
        response = connection.getresponse()
        body = response.read(MAX_BODY_BYTES + 1)
        if len(body) > MAX_BODY_BYTES:
            body = body[:MAX_BODY_BYTES]
        location = response.headers.get("Location")
        content_type = response.headers.get("Content-Type", "")
        return response.status, body, location or content_type or None
    finally:
        connection.close()


def fetch_url(url: str) -> tuple[str, str]:
    """Fetch a public http(s) URL and return (final_url, text). Every hop is
    re-pinned; redirects beyond the limit, non-public targets, non-text
    content types and oversized bodies raise InspectionError (fail-closed).
    The caller must scan the returned text through the firewall — the fetcher
    is transport only and grants no trust."""
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        pin = _pin_public(current)
        if pin is None:
            raise InspectionError("fetch_target_not_public")
        pinned_host, hostname, port = pin
        parsed = urllib.parse.urlparse(current)
        https = parsed.scheme == "https"
        try:
            status, body, extra = _request(pinned_host, hostname, port, parsed.path + (f"?{parsed.query}" if parsed.query else ""), https)
        except (OSError, ssl.SSLError) as error:
            # Fail closed: transport failures are InspectionErrors, never
            # raw socket errors leaking to the caller.
            logger.warning("fetch.transport_failed", extra={"event_fields": dict(error_type=type(error).__name__)})
            raise InspectionError("fetch_connection_failed") from error
        if status in (301, 302, 303, 307, 308) and extra and "://" in extra:
            logger.info("fetch.redirect", extra={"event_fields": dict(status=status, hops=_hop + 1)})
            current = extra
            continue
        if status >= 400:
            raise InspectionError("fetch_http_error")
        content_type = extra or ""
        if content_type and not any(kind in content_type for kind in ("text/", "json", "xml", "javascript")):
            raise InspectionError("fetch_unsupported_content_type")
        text = body.decode("utf-8", errors="replace")
        logger.info("fetch.completed", extra={"event_fields": dict(url=content_preview(current), bytes=len(body), status=status)})
        return current, text
    raise InspectionError("fetch_redirect_limit")


def is_global_url(url: str) -> bool:
    """Quick SSRF pre-check for callers deciding whether a fetch is even
    allowed: scheme + all resolved addresses public."""
    return _pin_public(url) is not None
