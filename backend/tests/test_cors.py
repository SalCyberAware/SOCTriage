"""Tests for the CORS policy in main.py.

The policy fails closed: with FRONTEND_URL unset no origin is allowed. The
middleware is built once at import, so these tests build a small app with the
same settings main.py uses, reading the environment as each test sets it.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

import main

FRONTEND = "https://soctriage.vercel.app"
OTHER = "https://evil.example"


def _client() -> TestClient:
    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=main.cors_allowed_origins(),
        allow_credentials=False,
        allow_methods=main.CORS_ALLOW_METHODS,
        allow_headers=main.CORS_ALLOW_HEADERS,
    )

    @app.get("/ping")
    def ping():
        return {"ok": True}

    return TestClient(app)


def _preflight(client: TestClient, origin: str, method: str, headers: str = ""):
    request_headers = {
        "Origin": origin,
        "Access-Control-Request-Method": method,
    }
    if headers:
        request_headers["Access-Control-Request-Headers"] = headers
    return client.options("/ping", headers=request_headers)


def test_unset_frontend_url_allows_no_origins(monkeypatch):
    monkeypatch.delenv("FRONTEND_URL", raising=False)
    assert main.cors_allowed_origins() == []


def test_blank_frontend_url_allows_no_origins(monkeypatch):
    monkeypatch.setenv("FRONTEND_URL", "   ")
    assert main.cors_allowed_origins() == []


def test_unset_frontend_url_rejects_preflight(monkeypatch):
    monkeypatch.delenv("FRONTEND_URL", raising=False)
    response = _preflight(_client(), FRONTEND, "POST", "content-type")
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_unset_frontend_url_adds_no_allow_origin_to_simple_request(monkeypatch):
    monkeypatch.delenv("FRONTEND_URL", raising=False)
    response = _client().get("/ping", headers={"Origin": FRONTEND})
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize(
    ("method", "headers"),
    [
        ("GET", ""),
        ("POST", "content-type"),
        ("PATCH", "content-type,x-api-key"),
    ],
)
def test_set_frontend_url_allows_what_the_app_sends(monkeypatch, method, headers):
    monkeypatch.setenv("FRONTEND_URL", FRONTEND)
    response = _preflight(_client(), FRONTEND, method, headers)
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == FRONTEND
    assert "access-control-allow-credentials" not in response.headers


def test_set_frontend_url_rejects_other_origins(monkeypatch):
    monkeypatch.setenv("FRONTEND_URL", FRONTEND)
    response = _preflight(_client(), OTHER, "POST", "content-type")
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_set_frontend_url_rejects_unused_method(monkeypatch):
    monkeypatch.setenv("FRONTEND_URL", FRONTEND)
    response = _preflight(_client(), FRONTEND, "DELETE")
    assert response.status_code == 400


def test_set_frontend_url_rejects_unlisted_header(monkeypatch):
    monkeypatch.setenv("FRONTEND_URL", FRONTEND)
    response = _preflight(_client(), FRONTEND, "POST", "x-custom-header")
    assert response.status_code == 400


def test_main_app_uses_the_same_policy():
    cors = [m for m in main.app.user_middleware if m.cls is CORSMiddleware]
    assert len(cors) == 1
    options = cors[0].kwargs
    assert options["allow_credentials"] is False
    assert options["allow_methods"] == main.CORS_ALLOW_METHODS
    assert options["allow_headers"] == main.CORS_ALLOW_HEADERS
    assert "*" not in options["allow_origins"]
