#!/usr/bin/env python3
"""
Script auxiliar: registra dois usuários de teste (A e B) no vAPI real,
calcula os tokens base64(email:senha) e imprime um bloco pronto para colar
no .env.

AVISO METODOLÓGICO IMPORTANTE: os campos exatos do corpo de registro/login
(nomes como "name", "email", "password") e os caminhos REGISTER_PATH/
LOGIN_PATH abaixo são uma reconstrução best-effort a partir da coleção
Postman pública do vAPI (github.com/roottusk/vapi) — NÃO foram confirmados
contra uma instância rodando. Essa validação só acontece na etapa 3 do
roteiro deste TCC, quando o vAPI estiver de pé via Docker.

Se o registro ou o login falharem, o script imprime a resposta bruta do
servidor e para — de propósito. A intenção é que você ajuste
REGISTER_PATH/LOGIN_PATH/payload/_extract_id() manualmente com base na
resposta real, documentando a divergência encontrada entre a spec manual e o
comportamento real da API (é exatamente o tipo de achado que vale registrar
no capítulo de metodologia), em vez de o script tentar "adivinhar" um novo
formato silenciosamente.
"""
from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys

import requests

from agent.config import Config

# Best-effort, não confirmado — ver aviso no topo do arquivo.
REGISTER_PATH = "/api1/auth/register"
LOGIN_PATH = "/api1/auth/login"


def _random_password() -> str:
    return secrets.token_urlsafe(12)


def register_user(base_url: str, label: str, email: str, password: str) -> dict:
    url = f"{base_url}{REGISTER_PATH}"
    payload = {
        "name": f"BOLA Test User {label}",
        "email": email,
        "password": password,
    }
    response = requests.post(url, json=payload, timeout=Config.REQUEST_TIMEOUT_S)
    if response.status_code >= 400:
        print(
            f"[setup] Falha ao registrar usuário {label} (HTTP {response.status_code}) em {url}.\n"
            f"Corpo enviado: {json.dumps(payload)}\n"
            f"Corpo da resposta: {response.text}\n"
            "Ajuste REGISTER_PATH e o payload em setup_vapi_users.py conforme "
            "o formato real do vAPI antes de rodar de novo.",
            file=sys.stderr,
        )
        response.raise_for_status()
    return response.json()


def _extract_id(payload: dict) -> str:
    """
    Tenta localizar o ID do usuário em formatos comuns de resposta
    (`id`, `_id`, aninhado em `user`/`data`...). Levanta erro explícito se
    não encontrar, em vez de assumir um caminho e falhar silenciosamente
    mais adiante no pipeline.
    """
    candidates = [payload.get("id"), payload.get("_id")]
    for key in ("user", "data"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            candidates += [nested.get("id"), nested.get("_id")]
    for candidate in candidates:
        if candidate:
            return str(candidate)
    raise ValueError(
        f"Não foi possível localizar o ID do usuário na resposta: {json.dumps(payload)}. "
        "Ajuste _extract_id() em setup_vapi_users.py conforme o formato real do vAPI."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=Config.TARGET_BASE_URL, help="URL base do vAPI (ex.: http://localhost/vapi)")
    args = parser.parse_args()

    env_lines = [f"TARGET_BASE_URL={args.base_url}"]

    for label in ("A", "B"):
        email = f"bola.test.{label.lower()}.{secrets.token_hex(4)}@example.test"
        password = _random_password()

        register_response = register_user(args.base_url, label, email, password)
        user_id = _extract_id(register_response)

        token = base64.b64encode(f"{email}:{password}".encode()).decode("ascii")

        env_lines += [
            f"USER_{label}_EMAIL={email}",
            f"USER_{label}_PASSWORD={password}",
            f"USER_{label}_ID={user_id}",
            f"USER_{label}_TOKEN={token}",
        ]
        print(f"[setup] Usuário {label} registrado: id={user_id}, email={email}")

    print("\n# Cole o bloco abaixo no seu .env:\n")
    print("\n".join(env_lines))


if __name__ == "__main__":
    main()
