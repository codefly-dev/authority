"""The transport rule for dialling the authority host, as a module served in Python
applies it: the Go library's ``host.Target`` / ``host.Endpoint``
(``libraries/authority-client/go/host``), rule for rule.

``https://`` is verified TLS. Plaintext (``http://``, ``grpc://``, ``tcp://`` or a bare
``host:port``) is admitted only to a loopback address in a local run, or to an
in-cluster Service address (``<svc>.<ns>.svc[.cluster.local]``) under the
composition's literal assertion that a mutually authenticated mesh carries the hop
(``internal-transport/mesh-protected=true``). Anything else is refused, by name, and a
refusal names the endpoint by its host and port alone: never the raw value, which may
carry a credential.

Where the two inputs come from, as the Go library reads them from its own SDK:

- ``local``: whether the run is in the environment named exactly ``local``, as Go's
  ``codefly.IsLocal()`` decides it: ``os.environ.get("CODEFLY__ENVIRONMENT") ==
  "local"``. No name prefix is reserved for local runs (a playground's
  ``local-authority`` is a configuration profile of ``local``). Do not use the Python
  SDK's ``is_local``, which reads the wrong variable (codefly-dev/sdk-python#8).
- ``mesh``: the raw workspace value ``internal-transport/mesh-protected``, as the
  Codefly Python SDK delivers it (``codefly.configuration(name="internal-transport",
  key="mesh-protected")``); ``None`` when the composition sets none.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import grpc

__all__ = ["Refused", "Target", "endpoint", "dial", "mesh_protected", "ALLOWED_OPTIONS"]

# The channel options a caller may set: liveness, message sizes, reconnection and
# the user agent. Anything else (a proxy, a TLS override, an authority override, a
# service config) could route or verify the channel otherwise, so it is refused.
ALLOWED_OPTIONS = frozenset({
    "grpc.keepalive_time_ms",
    "grpc.keepalive_timeout_ms",
    "grpc.keepalive_permit_without_calls",
    "grpc.http2.max_pings_without_data",
    "grpc.max_send_message_length",
    "grpc.max_receive_message_length",
    "grpc.initial_reconnect_backoff_ms",
    "grpc.min_reconnect_backoff_ms",
    "grpc.max_reconnect_backoff_ms",
    "grpc.primary_user_agent",
})

PLAINTEXT_SCHEMES = ("http", "grpc", "tcp")
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class Refused(ValueError):
    """The endpoint may not be dialled; the message names the rule, never the value."""


@dataclass(frozen=True)
class Target:
    """A gRPC target and whether it is reached over TLS."""

    address: str
    tls: bool


def mesh_protected(value: str | None) -> bool:
    """The composition's ``internal-transport/mesh-protected``: unset, empty or
    ``false`` is no assertion; exactly ``true`` is one; anything else is refused."""
    if value is None or value == "" or value == "false":
        return False
    if value != "true":
        raise Refused("internal-transport/mesh-protected must be exactly true or false")
    return True


def endpoint(value: str, *, local: bool, mesh: str | None) -> Target:
    """The target for ``value`` (authority/endpoint, or an explicit upstream) under the
    transport rule, or ``Refused`` naming why."""
    asserted = mesh_protected(mesh)
    # Control characters are judged on the raw value, before strip() (which also
    # removes \x1c-\x1f), exactly as Go judges them before TrimSpace.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in (value or "")):
        raise Refused("authority/endpoint carries a control character (value not shown: it may carry a credential)")
    value = (value or "").strip()
    if not value:
        raise Refused("transport endpoint is empty; supply a resolved endpoint")
    if "://" not in value:
        host = _split_host_port(value)
        if host is None:
            raise Refused(
                "authority/endpoint is neither host:port nor a URL "
                "(value not shown: it may carry a credential)"
            )
        return _plaintext(value, host, local, asserted)
    try:
        parts = urlsplit(value)
        port = parts.port
        hostname = parts.hostname
    except ValueError:
        raise Refused("authority/endpoint (unparseable) is not an origin") from None
    named = _host_only(parts.netloc)
    if (
        not hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.path not in ("", "/")
    ):
        raise Refused(
            f"authority/endpoint {named} is not an origin: it must carry no credential, "
            "path, query or fragment"
        )
    host = f"[{hostname}]" if ":" in hostname else hostname
    if parts.scheme == "https":
        if port == 0:
            raise Refused(f"authority/endpoint {named} names no port in 1-65535")
        return Target(f"{host}:{443 if port is None else port}", True)
    if parts.scheme in PLAINTEXT_SCHEMES:
        return _plaintext(f"{host}:{80 if port is None else port}", hostname, local, asserted)
    raise Refused(
        f"authority/endpoint {named} names scheme {parts.scheme!r}; "
        "the host is reached over http:// (h2c) or https://"
    )


def dial(value: str, *, local: bool, mesh: str | None, options=()) -> grpc.Channel:
    """A channel to ``value`` under the transport rule (``endpoint``). ``options`` may
    only be ``ALLOWED_OPTIONS``: nothing that routes or verifies the channel otherwise."""
    for key, _ in options:
        if key not in ALLOWED_OPTIONS:
            raise Refused(f"channel option {key} is not one a caller may set (ALLOWED_OPTIONS)")
    target = endpoint(value, local=local, mesh=mesh)
    if target.tls:
        return grpc.secure_channel(target.address, grpc.ssl_channel_credentials(), options=options)
    return grpc.insecure_channel(target.address, options=options)


def _plaintext(target: str, hostname: str, local: bool, mesh: bool) -> Target:
    port = target.rsplit(":", 1)[-1]
    if not (port.isascii() and port.isdigit()) or not 1 <= int(port) <= 65535:
        raise Refused("authority endpoint names no port in 1-65535")
    if not (local and _loopback(hostname)) and not (mesh and _cluster_service(hostname)):
        raise Refused(
            "authority endpoint requires HTTPS, local loopback, or an in-cluster Service "
            "address with internal-transport/mesh-protected=true"
        )
    return Target(target, False)


def _split_host_port(value: str) -> str | None:
    match = re.fullmatch(r"\[([^\]]+)\]:([0-9]{1,5})|([^:\[\]/@?#\s]+):([0-9]{1,5})", value)
    if match is None:
        return None
    return match.group(1) or match.group(3)


def _loopback(hostname: str) -> bool:
    if "%" in hostname:  # a zone id: Go's net.ParseIP admits none
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _cluster_service(hostname: str) -> bool:
    """The mesh assertion covers Service DNS names, never arbitrary hosts or IPs."""
    labels = hostname.lower().removesuffix(".").split(".")
    if len(labels) not in (3, 5) or labels[2] != "svc":
        return False
    if len(labels) == 5 and labels[3:] != ["cluster", "local"]:
        return False
    return all(_LABEL.match(label) for label in labels[:2])


def _host_only(netloc: str) -> str:
    """The host and port of a netloc, without userinfo."""
    host = netloc.rsplit("@", 1)[-1]
    return host or "(unparseable)"
