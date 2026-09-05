"""
Configuração centralizada do agente.

Toda credencial e URL de alvo vem de variáveis de ambiente (.env) — nunca
hardcoded — justamente para reduzir o risco de este código, escrito para um
laboratório vulnerável por design (vAPI), ser reaproveitado sem querer contra
qualquer outro alvo.

Os atributos de classe abaixo (URLs, nomes de cabeçalho, flags) têm defaults
seguros e podem ser lidos mesmo sem um .env completo — isso é o que permite
rodar o parser/inferência/geração de casos offline (--dry-run) sem qualquer
configuração de rede. Já os métodos `user_a()` / `user_b()` /
`require_network_config()` são explicitamente carregados sob demanda pelas
etapas que realmente precisam de credenciais (executor.py,
setup_vapi_users.py), para que a ausência delas só quebre quem depende delas.
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    return os.environ.get(name, default)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class Identity:
    """Um usuário de teste (A ou B) usado nos ataques cruzados de BOLA."""

    label: str
    email: Optional[str]
    password: Optional[str]
    resource_id: Optional[str]
    token: Optional[str] = None

    def auth_token(self) -> str:
        """
        Retorna o token pronto para o cabeçalho de autenticação.

        Se USER_[A|B]_TOKEN já estiver definido no .env, usamos ele
        diretamente — é o que setup_vapi_users.py grava depois de registrar
        os usuários reais. Caso contrário, calculamos base64(email:senha)
        on-the-fly, o que é útil para configurar um cenário de teste manual
        sem depender do script de setup.
        """
        if self.token:
            return self.token
        if self.email is None or self.password is None:
            raise ValueError(
                f"Identidade '{self.label}' não tem token nem email/senha configurados."
            )
        raw = f"{self.email}:{self.password}".encode("utf-8")
        return base64.b64encode(raw).decode("ascii")


class Config:
    # --- Alvo ---
    TARGET_BASE_URL: str = _env("TARGET_BASE_URL", "http://localhost/vapi")
    REQUEST_TIMEOUT_S: float = _env_float("REQUEST_TIMEOUT_S", 10.0)
    REQUEST_DELAY_MS: float = _env_float("REQUEST_DELAY_MS", 150.0)

    # --- Autenticação do módulo API1/API5 do vAPI ---
    # DECISÃO DE DESIGN: o vAPI não usa "Authorization: Bearer <token>" como a
    # maioria das specs OpenAPI de exemplo assume — ele usa um cabeçalho
    # customizado contendo base64(usuario:senha). Isso é parametrizado aqui
    # (em vez de fixo em http_client.py/executor.py) para que, se este agente
    # for reaproveitado contra outro alvo do mesmo TCC com esquema de auth
    # diferente, baste trocar estas duas variáveis.
    AUTH_HEADER_NAME: str = _env("AUTH_HEADER_NAME", "Authorization-Token")
    AUTH_HEADER_FORMAT: str = _env("AUTH_HEADER_FORMAT", "{token}")

    # --- Especificação ---
    OPENAPI_SPEC_PATH: Path = Path(
        _env("OPENAPI_SPEC_PATH", str(PROJECT_ROOT / "specs" / "vapi_openapi.json"))
    )

    # --- LLM (Anthropic) ---
    ANTHROPIC_API_KEY: Optional[str] = _env("ANTHROPIC_API_KEY")
    LLM_MODEL: str = _env("LLM_MODEL", "claude-opus-5")
    USE_LLM_FOR_RELATION_INFERENCE: bool = _env_bool("USE_LLM_FOR_RELATION_INFERENCE", True)
    USE_LLM_FOR_CLASSIFICATION: bool = _env_bool("USE_LLM_FOR_CLASSIFICATION", True)

    # --- Saída ---
    RUNS_DIR: Path = Path(_env("RUNS_DIR", str(PROJECT_ROOT / "runs")))

    @staticmethod
    def build_auth_header(token: str) -> dict:
        """Monta o cabeçalho HTTP de autenticação a partir do token bruto."""
        header_value = Config.AUTH_HEADER_FORMAT.format(token=token)
        return {Config.AUTH_HEADER_NAME: header_value}

    @staticmethod
    def user_a() -> Identity:
        return Identity(
            label="A",
            email=_env("USER_A_EMAIL"),
            password=_env("USER_A_PASSWORD"),
            resource_id=_env("USER_A_ID"),
            token=_env("USER_A_TOKEN"),
        )

    @staticmethod
    def user_b() -> Identity:
        return Identity(
            label="B",
            email=_env("USER_B_EMAIL"),
            password=_env("USER_B_PASSWORD"),
            resource_id=_env("USER_B_ID"),
            token=_env("USER_B_TOKEN"),
        )

    @staticmethod
    def require_network_config() -> None:
        """
        Valida a configuração mínima para etapas que fazem chamadas HTTP reais
        (executor.py via orchestrator.py, setup_vapi_users.py). Chamado
        explicitamente por essas etapas — nunca no import do módulo — para
        que o uso só-offline (parser/inferência/geração de casos) não exija
        um .env completo.
        """
        missing = []
        for name in ("USER_A_ID", "USER_B_ID"):
            if not _env(name):
                missing.append(name)
        for ident in (Config.user_a(), Config.user_b()):
            try:
                ident.auth_token()
            except ValueError:
                missing.append(f"USER_{ident.label}_TOKEN ou USER_{ident.label}_EMAIL/PASSWORD")
        if missing:
            raise RuntimeError(
                "Configuração incompleta para execução contra o vAPI real. "
                f"Faltando: {', '.join(missing)}. Rode setup_vapi_users.py "
                "primeiro ou preencha o .env manualmente."
            )
