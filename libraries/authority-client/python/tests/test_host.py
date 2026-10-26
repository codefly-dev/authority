"""authority_client.host holds the Go library's host.Target rule, case for case
(libraries/authority-client/go/host/host_test.go)."""

import pytest

from authority_client.host import Refused, Target, dial, endpoint, mesh_protected


@pytest.mark.parametrize(
    "value, want",
    [
        ("localhost:9000", Target("localhost:9000", False)),
        ("http://localhost:8080", Target("localhost:8080", False)),
        ("http://localhost", Target("localhost:80", False)),
        ("grpc://localhost:9000", Target("localhost:9000", False)),
        ("http://127.0.0.1", Target("127.0.0.1:80", False)),
        ("http://[::1]", Target("[::1]:80", False)),
        ("https://accounts.example.test", Target("accounts.example.test:443", True)),
        ("https://accounts.example.test:8443/", Target("accounts.example.test:8443", True)),
    ],
)
def test_the_configured_endpoint_in_a_local_run(value, want):
    assert endpoint(value, local=True, mesh=None) == want


@pytest.mark.parametrize(
    "value",
    ["", "  ", "accounts", "ftp://accounts:21", "https://accounts/v1", "https://u:p@accounts",
     "http://accounts:1?x=1", "http://"],
)
def test_what_is_not_an_origin_is_refused(value):
    with pytest.raises(Refused):
        endpoint(value, local=True, mesh=None)


@pytest.mark.parametrize(
    "value",
    ["remote.test:8080", "http://remote.test", "grpc://10.0.0.2:443", "tcp://[2001:db8::1]:8080",
     "http://10.0.0.5:9000", "http://authority.attacker.example:80"],
)
def test_plaintext_to_a_routable_host_is_refused(value):
    for mesh in (None, "true"):
        with pytest.raises(Refused, match="requires HTTPS"):
            endpoint(value, local=True, mesh=mesh)


def test_loopback_plaintext_is_local_only():
    with pytest.raises(Refused):
        endpoint("http://127.0.0.1:8080", local=False, mesh=None)


VALID = ("accounts.platform.svc", "accounts.platform.svc.cluster.local", "accounts.platform.svc.cluster.local.")
NAMES = VALID + ("10.0.0.2", "remote.test", "localhost", "accounts.platform.svc.evil.test", "accounts..svc",
                 "-accounts.platform.svc", "accounts.plat_form.svc")


@pytest.mark.parametrize("assertion", [None, "", "false", "true"])
@pytest.mark.parametrize("name", NAMES)
def test_an_in_cluster_service_is_plaintext_only_under_the_mesh_assertion(assertion, name):
    allowed = assertion == "true" and name in VALID
    try:
        target = endpoint(f"http://{name}:8080", local=False, mesh=assertion)
    except Refused:
        assert not allowed
    else:
        assert allowed and target == Target(f"{name}:8080", False)


@pytest.mark.parametrize("assertion", ["TRUE", " true", "true ", "yes"])
def test_a_misspelt_assertion_is_refused_even_over_tls(assertion):
    with pytest.raises(Refused, match="exactly true or false"):
        mesh_protected(assertion)
    with pytest.raises(Refused):
        endpoint("https://accounts.example.test", local=False, mesh=assertion)


SECRET = "s3cr3t-token"


@pytest.mark.parametrize(
    "value",
    [
        f"https://user:{SECRET}@authority.example:8443",
        f"https://authority.example:8443/?token={SECRET}",
        f"https://authority.example:8443/{SECRET}",
        f"https://authority.example:8443/#{SECRET}",
        f"ftp://authority.example:21?k={SECRET}",
        f"ftp://{SECRET}@authority.example:21",
        f"{SECRET}-not-an-address",
        f"https://[{SECRET}",
    ],
)
def test_a_refusal_never_echoes_the_endpoint_value(value):
    with pytest.raises(Refused) as refused:
        endpoint(value, local=True, mesh=None)
    assert SECRET not in str(refused.value)


# Review r61 m1 and r74 m1: the same table as Go's
# TestControlCharactersZoneIDsAndInvalidPortsAreRefused.
@pytest.mark.parametrize("value", [
    "http://127.0.0.1\t:80", "http://local\nhost:80", "127.0.0.1\t:80", "localhost:80\x7f",
    "\x1clocalhost:7000", "\x1flocalhost:7000", "\tlocalhost:7000", "localhost:7000\n",
    "http://[::1%25lo0]:80", "[::1%lo0]:80", "http://127.0.0.1:0", "127.0.0.1:0", "localhost:00",
    "https://accounts.example.test:0", "localhost:", "127.0.0.1:", "localhost:+80", "localhost: 80",
    "localhost:-1", "localhost:65536", "http://localhost:+80", "https://accounts.example.test:65536",
    "localhost:\u0663\u0663",
])
def test_control_characters_zone_ids_and_invalid_ports_are_refused(value):
    with pytest.raises(Refused) as refused:
        endpoint(value, local=True, mesh=None)
    assert "\t" not in str(refused.value) and "\n" not in str(refused.value)


# Review r61 m3 and r74 m2: only allowlisted options; a proxy, a TLS or authority
# override or a service config could route or verify the channel otherwise.
@pytest.mark.parametrize("option", ["grpc.ssl_target_name_override", "grpc.default_authority", "grpc.http_proxy",
                                    "grpc.service_config", "grpc.enable_http_proxy"])
def test_dial_admits_only_allowlisted_options(option):
    with pytest.raises(Refused, match="ALLOWED_OPTIONS"):
        dial("https://accounts.example.test", local=False, mesh=None, options=[(option, "evil.example")])
    dial("https://accounts.example.test", local=False, mesh=None, options=[("grpc.keepalive_time_ms", 30000)]).close()
