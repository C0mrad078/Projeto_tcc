"""
Interface formal de "adapter" de identidade (Fase 8 da refatoração
metodológica do TCC — generalização).

DECISÃO DE DESIGN: até esta refatoração, `Config.identity()` sempre
resolvia credenciais por `(módulo, rótulo)` — `USER_A_API1_*`,
`USER_A_API5_*`, etc. Essa é a modelagem CORRETA para o vAPI (cada módulo
tem sua própria tabela de usuários, sem relação entre si — ver docstring de
config.py), mas é desnecessariamente complexa para um alvo hipotético com
uma única base de usuários compartilhada entre todos os endpoints (o caso
mais comum fora do vAPI).

Este módulo formaliza os dois casos como implementações intercambiáveis de
`IdentityProvider`, escolhidas por `IDENTITY_STRATEGY` no `.env`:
  - "per_module" (default — mantém o comportamento validado do vAPI)
  - "shared" (um par de credenciais só, reaproveitado em qualquer módulo)

Isso NÃO é uma reescrita de `Config.identity()` — é uma extração: o
comportamento default continua bit-a-bit idêntico ao que já existia,
validado contra o vAPI real sem regressão (ver README).
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # evita import circular em tempo de execução — ver config.py
    from .config import Identity


class IdentityProvider(ABC):
    """Como o agente obtém as credenciais de teste (A/B) para um dado módulo de um alvo."""

    @abstractmethod
    def get(self, module: str, label: str) -> "Identity":
        ...


class PerModuleIdentityProvider(IdentityProvider):
    """
    Estratégia validada do vAPI: credenciais próprias por módulo
    (USER_A_API1_*, USER_A_API5_*, ...) — necessária porque, no vAPI, cada
    módulo tem sua própria tabela de usuários, sem nenhuma relação entre si.
    """

    def get(self, module: str, label: str) -> "Identity":
        from .config import Identity  # import tardio: Identity vive em config.py, que importa este módulo

        prefix = f"USER_{label}_{module.upper()}"
        return Identity(
            label=label,
            username=os.environ.get(f"{prefix}_USERNAME"),
            password=os.environ.get(f"{prefix}_PASSWORD"),
            resource_id=os.environ.get(f"{prefix}_ID"),
            token=os.environ.get(f"{prefix}_TOKEN"),
        )


class SharedIdentityProvider(IdentityProvider):
    """
    Estratégia genérica para um alvo com UMA base de usuários compartilhada
    entre todos os endpoints — ignora `module`, lê só USER_A_*/USER_B_* sem
    sufixo de módulo. É o caso mais simples e mais comum fora do vAPI.
    """

    def get(self, module: str, label: str) -> "Identity":
        from .config import Identity

        prefix = f"USER_{label}"
        return Identity(
            label=label,
            username=os.environ.get(f"{prefix}_USERNAME"),
            password=os.environ.get(f"{prefix}_PASSWORD"),
            resource_id=os.environ.get(f"{prefix}_ID"),
            token=os.environ.get(f"{prefix}_TOKEN"),
        )


_STRATEGIES = {
    "per_module": PerModuleIdentityProvider,
    "shared": SharedIdentityProvider,
}


def build_identity_provider(strategy: str) -> IdentityProvider:
    provider_cls = _STRATEGIES.get(strategy)
    if provider_cls is None:
        print(
            f"[adapters] Aviso: IDENTITY_STRATEGY='{strategy}' desconhecida "
            f"(esperado um de {list(_STRATEGIES)}); usando 'per_module'."
        )
        provider_cls = PerModuleIdentityProvider
    return provider_cls()
