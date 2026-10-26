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

The caller supplies what its SDK resolved, as the Go library reads it from its own:
whether the run is local, and the raw ``internal-transport/mesh-protected`` value.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import grpc

__all__ = ["Refused", "Target", "endpoint", "dial", "mesh_protected"]

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
        return Target(f"{host}:{port or 443}", True)
    if parts.scheme in PLAINTEXT_SCHEMES:
        return _plaintext(f"{host}:{port or 80}", hostname, local, asserted)
    raise Refused(
        f"authority/endpoint {named} names scheme {parts.scheme!r}; "
        "the host is reached over http:// (h2c) or https://"
    )


def dial(value: str, *, local: bool, mesh: str | None, options=()) -> grpc.Channel:
    """A channel to ``value`` under the transport rule (``endpoint``)."""
    target = endpoint(value, local=local, mesh=mesh)
    if target.tls:
        return grpc.secure_channel(target.address, grpc.ssl_channel_credentials(), options=options)
    return grpc.insecure_channel(target.address, options=options)


def _plaintext(target: str, hostname: str, local: bool, mesh: bool) -> Target:
    if not (local and _loopback(hostname)) and not (mesh and _cluster_service(hostname)):
        raise Refused(
            "authority endpoint requires HTTPS, local loopback, or an in-cluster Service "
            "address with internal-transport/mesh-protected=true"
        )
    return Target(target, False)


def _split_host_port(value: str) -> str | None:
    match = re.fullmatch(r"\[([^\]]+)\]:(\d{1,5})|([^:\[\]/@?#\s]+):(\d{1,5})", value)
    if match is None:
        return None
    return match.group(1) or match.group(3)


def _loopback(hostname: str) -> bool:
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
