"""The isolated fetcher must never reach private, internal or metadata addresses (SSRF)."""

import socket

import pytest
from fastapi.testclient import TestClient

from app.fetcher import net
from app.fetcher.service import app as fetcher_app


def resolver(mapping):
    def fake(host, port, *a, **k):
        if host not in mapping:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[host], port))]

    return fake


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/admin",
        "http://[::1]/",
        "http://100.64.0.1/",
        "http://metadata.google.internal/",
        "http://localhost:6379/",
    ],
)
def test_private_and_metadata_targets_are_refused(url, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", resolver({"localhost": "127.0.0.1"}))
    out = net.fetch(url)
    assert not out.ok
    assert out.unsafe or "Port" in (out.error or "")


def test_hostnames_resolving_to_private_addresses_are_refused(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", resolver({"evil.example": "192.168.0.10"}))
    out = net.fetch("http://evil.example/")
    assert out.unsafe and "private" in out.error


def test_each_redirect_hop_is_validated(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        resolver({"start.example": "93.184.216.34", "internal.example": "10.1.2.3"}),
    )
    calls = []
    real = net._one_request

    def fake(url, timeout, max_bytes):
        calls.append(url)
        if url.startswith("http://start.example"):
            return (
                302,
                {"location": "http://internal.example/secret"},
                b"",
                False,
                "93.184.216.34",
                5,
                False,
            )
        return real(url, timeout, max_bytes)

    monkeypatch.setattr(net, "_one_request", fake)
    out = net.fetch("http://start.example/")
    assert calls[0] == "http://start.example/" and out.unsafe
    assert [h.url for h in out.hops] == ["http://start.example/"]


def test_unusual_ports_are_refused(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", resolver({"x.example": "93.184.216.34"}))
    out = net.fetch("http://x.example:22/")
    assert out.unsafe and "Port 22" in out.error


def test_redirect_limit(monkeypatch):
    monkeypatch.setattr(
        net,
        "_one_request",
        lambda url, t, m: (301, {"location": url + "x"}, b"", False, "93.184.216.34", 1, False),
    )
    out = net.fetch("http://loop.example/", max_redirects=3)
    assert not out.ok and "redirects" in out.error and len(out.hops) == 4


def test_fetcher_service_requires_its_token(monkeypatch):
    monkeypatch.setenv("FETCHER_TOKEN", "t" * 32)
    client = TestClient(fetcher_app)
    assert client.post("/fetch", json={"url": "http://x.example/"}).status_code == 401
    monkeypatch.setattr("app.fetcher.service.fetch", lambda url, **kw: net.FetchOutcome(url))
    r = client.post(
        "/fetch", json={"url": "http://x.example/"}, headers={"x-fetcher-token": "t" * 32}
    )
    assert r.status_code == 200 and r.json()["requested_url"] == "http://x.example/"


def test_fetcher_module_has_no_database_or_secret_imports():
    import ast
    import inspect

    tree = ast.parse(
        inspect.getsource(net)
        + inspect.getsource(__import__("app.fetcher.service", fromlist=["x"]))
    )
    imported = {(n.module or "") for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | {
        a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names
    }
    assert not any(
        m.startswith(("app.core", "app.models", "sqlalchemy", "redis")) for m in imported
    )
