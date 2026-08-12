"""SSRF guard for caller-supplied webhook URLs.

`AuditRequest.callback_url` (main.py) lets a caller tell this API where to
POST a job's result. That URL is attacker-controlled input from the worker's
perspective: nothing stops a caller from pointing it at the worker's own
cloud metadata endpoint, a loopback-bound admin port, or an internal service
on the deployment's private network.

The check is split in two on purpose:

* `validate_url_scheme` is pure string work. Safe to call from anywhere,
  including a Pydantic validator running inside the event loop.
* `validate_webhook_url` additionally resolves DNS, which **blocks**.
  `socket.getaddrinfo` has no timeout and a hostname served by a
  deliberately slow authoritative nameserver can stall the calling thread
  for a long time — so callers on an event loop must use
  `validate_webhook_url_async`, which pushes it to a worker thread. Calling
  the blocking form directly from `async def` code would let one caller-
  supplied hostname stall the whole API process.

It runs twice per job (see main.py and worker.py) — once at submission so a
bad URL is rejected before a queue slot is spent, and again immediately
before delivery, since DNS can change in between.

Known, deliberate residual risk (documented rather than hidden, matching this
repo's convention — see worker.py's TOCTOU/cancellation comments): there is a
small window between the DNS resolution this module performs and the
resolution the HTTP client performs when it actually connects. Fully closing
that (DNS pinning: resolve once, connect to the pinned IP, send the original
hostname via SNI/Host header) is a real fix but adds real complexity for a
best-effort notification feature. Re-validating at delivery time narrows the
window to the gap between the two checks rather than the job's entire
lifetime; closing it completely is an explicit scope cut for this pass, not
an oversight. Two things bound the damage meanwhile: delivery never follows
redirects, and the response is never returned to the caller (only logged),
so what survives is blind SSRF, not a read primitive.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

# https only. Rules out `file://`, `gopher://`, `ftp://`, and plain `http://`
# (which would let a signed webhook still be sent in cleartext) in one check.
_ALLOWED_SCHEMES = {"https"}


def _is_disallowed_address(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)

    # An IPv4-mapped IPv6 address (`::ffff:127.0.0.1`) has to be judged by the
    # IPv4 address it embeds, or `https://[::ffff:127.0.0.1]/` walks straight
    # past a v6-only check to loopback. CPython only started doing that itself
    # in 3.13 (backported into later 3.12 patch releases), so unwrapping it
    # here rather than trusting the interpreter keeps the guard from silently
    # weakening on an older patch level than the one this was tested against.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped

    # `not is_global` is the primary test, not `is_private`. They are not
    # complements: CPython documents `is_private` as deliberately False for
    # RFC 6598 carrier-grade NAT (100.64.0.0/10), so an is_private-based
    # check lets that entire /10 through — and it is real internal space in
    # cloud and ISP networks. Verified on 3.12.5 and 3.14.6:
    # `ip_address("100.64.0.1").is_private` is False on both.
    #
    # multicast and reserved are still checked explicitly because is_global
    # is True for some of them — the NAT64 prefix 64:ff9b::/96 is the case
    # that motivated it.
    return (not ip.is_global) or ip.is_multicast or ip.is_reserved


def validate_url_scheme(url: str) -> None:
    """The no-I/O half of the check. Raises ValueError if `url` is not a
    plausible webhook target on syntax alone. Cheap enough to run inside a
    Pydantic validator on the event loop."""
    parsed = urlparse(url)

    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError(
            f"callback_url must use one of {sorted(_ALLOWED_SCHEMES)}, got {parsed.scheme!r}"
        )

    if not parsed.hostname:
        raise ValueError("callback_url has no hostname")


def validate_webhook_url(url: str) -> None:
    """Full check, including DNS. Raises ValueError with a specific reason if
    `url` is not a safe delivery target; returns None if it is.

    BLOCKING — resolves DNS. From `async def` code use
    `validate_webhook_url_async` instead.
    """
    validate_url_scheme(url)
    hostname = urlparse(url).hostname

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as err:
        raise ValueError(f"callback_url hostname could not be resolved: {err}") from err

    if not addr_infos:
        raise ValueError("callback_url hostname resolved to no addresses")

    # Every returned address must pass, not just the first. A hostname can
    # resolve to a public address and a private one; accepting it because one
    # of them looked fine would let the connect() pick the other.
    for _family, _type, _proto, _canonname, sockaddr in addr_infos:
        # sockaddr[0] can carry a zone id on link-local IPv6 ("fe80::1%eth0");
        # ipaddress.ip_address rejects that suffix, and such an address is
        # being blocked either way, so strip it rather than let it raise the
        # wrong exception type out of this function.
        addr = sockaddr[0].split("%", 1)[0]
        if _is_disallowed_address(addr):
            raise ValueError(f"callback_url resolves to a disallowed address: {addr}")


async def validate_webhook_url_async(url: str) -> None:
    """Event-loop-safe wrapper around `validate_webhook_url`.

    The DNS lookup goes to a worker thread so a caller-supplied hostname
    whose nameserver never answers stalls one pool thread instead of the
    process's entire event loop.
    """
    await asyncio.to_thread(validate_webhook_url, url)
