"""Testes de agent/adapters.py — as duas estratégias de identidade (Fase 8: generalização)."""
from __future__ import annotations

from agent.adapters import PerModuleIdentityProvider, SharedIdentityProvider, build_identity_provider


def test_per_module_provider_scopes_by_module(monkeypatch):
    monkeypatch.setenv("USER_A_API1_USERNAME", "u_api1")
    monkeypatch.setenv("USER_A_API5_USERNAME", "u_api5")

    provider = PerModuleIdentityProvider()
    assert provider.get("api1", "A").username == "u_api1"
    assert provider.get("api5", "A").username == "u_api5"


def test_shared_provider_ignores_module(monkeypatch):
    monkeypatch.setenv("USER_A_USERNAME", "shared_user")

    provider = SharedIdentityProvider()
    assert provider.get("api1", "A").username == "shared_user"
    assert provider.get("qualquer_outro_modulo", "A").username == "shared_user"


def test_build_identity_provider_default_is_per_module():
    assert isinstance(build_identity_provider("per_module"), PerModuleIdentityProvider)


def test_build_identity_provider_shared():
    assert isinstance(build_identity_provider("shared"), SharedIdentityProvider)


def test_build_identity_provider_unknown_falls_back_to_per_module(capsys):
    provider = build_identity_provider("estrategia_inexistente")
    assert isinstance(provider, PerModuleIdentityProvider)
    assert "desconhecida" in capsys.readouterr().out
