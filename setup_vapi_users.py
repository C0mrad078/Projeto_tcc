#!/usr/bin/env python3
"""
Script auxiliar: registra os usuários de teste (A e B) nos módulos API1 e
API5 do vAPI real, calcula os tokens base64(username:senha) e imprime um
bloco pronto para colar no .env.

DECISÕES DE DESIGN CONFIRMADAS POR LEITURA DO CÓDIGO-FONTE DO VAPI (Laravel):
- API1 e API5 têm tabelas de usuários totalmente separadas
  (a_p_i1_users / a_p_i5_users), com IDs e credenciais independentes — por
  isso registramos 4 contas (A e B, em cada um dos dois módulos), não 2.
- Não existe endpoint de login em nenhum dos dois módulos. O "token" é só
  base64(username:senha) calculado pelo cliente; o backend decodifica o
  cabeçalho Authorization-Token e compara username/senha diretamente com a
  tabela (ver app/CustomClasses/CustomHeaderAuth.php). Por isso este script
  só registra e nunca tenta autenticar.
- Campos de registro exatos, confirmados contra App\\Http\\Controllers\\
  API1UsersController::store / API5UsersController::store e o dump SQL
  (colunas NOT NULL sem default):
    POST /api1/user -> {username, name, course, password}   (username é UNIQUE)
    POST /api5/user -> {username, password, name, address, mobileno}

NOTA DE GENERALIZAÇÃO (Fase 8 da refatoração metodológica do TCC): este
script é o "adapter" específico do vAPI — a ÚNICA peça do projeto que sabe o
formato exato de registro de usuário deste alvo em particular. O CORE do
agente (agent/relation_inference.py, test_generator.py, executor.py,
classifier.py) é genérico: não sabe nada sobre "username"/"course"/vAPI, só
consome Identity (username/password/resource_id/token) e uma spec OpenAPI.
Portar o agente para outro alvo significa escrever um script equivalente a
este (registro de usuários daquele alvo) — não tocar no core. Ainda não
existe uma interface formal de "adapter" (ex.: uma classe abstrata) porque só
há um alvo validado até agora; ver README, seção "Limitações", para essa
lacuna registrada explicitamente.
"""
from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys

import requests

from agent.config import Config

REGISTER_PATH = {
    "api1": "/api1/user",
    "api5": "/api5/user",
}


def _random_password() -> str:
    return secrets.token_urlsafe(12)


def _register_payload(module: str, username: str, password: str) -> dict:
    if module == "api1":
        return {"username": username, "name": f"BOLA Test {username}", "course": "TCC BOLA Test", "password": password}
    if module == "api5":
        return {
            "username": username,
            "password": password,
            "name": f"BOLA Test {username}",
            "address": "N/A",
            "mobileno": "0000000000",
        }
    raise ValueError(f"Módulo desconhecido: {module}")


def register_user(base_url: str, module: str, username: str, password: str) -> dict:
    url = f"{base_url}{REGISTER_PATH[module]}"
    payload = _register_payload(module, username, password)
    response = requests.post(url, json=payload, timeout=Config.REQUEST_TIMEOUT_S)
    if response.status_code >= 400:
        print(
            f"[setup] Falha ao registrar em {module} (HTTP {response.status_code}) em {url}.\n"
            f"Corpo enviado: {json.dumps(payload)}\n"
            f"Corpo da resposta: {response.text}\n"
            "Ajuste REGISTER_PATH/_register_payload() em setup_vapi_users.py "
            "conforme o formato real do vAPI antes de rodar de novo.",
            file=sys.stderr,
        )
        response.raise_for_status()
    return response.json()


def _extract_id(payload: dict) -> str:
    """
    Localiza o ID do usuário na resposta. Os controllers API1/API5 retornam
    diretamente o modelo Eloquent criado (API1Users::create(...) /
    API5Users::create(...)), então o campo esperado é "id" no nível raiz —
    mas mantemos os fallbacks abaixo caso essa suposição mude em outra versão.
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
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=Config.TARGET_BASE_URL, help="URL base do vAPI (ex.: http://localhost:8000/vapi)")
    args = parser.parse_args()

    env_lines = [f"TARGET_BASE_URL={args.base_url}"]

    for module in ("api1", "api5"):
        for label in ("A", "B"):
            username = f"bola{label.lower()}{secrets.token_hex(3)}"
            password = _random_password()

            register_response = register_user(args.base_url, module, username, password)
            user_id = _extract_id(register_response)

            token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")

            prefix = f"USER_{label}_{module.upper()}"
            env_lines += [
                f"{prefix}_USERNAME={username}",
                f"{prefix}_PASSWORD={password}",
                f"{prefix}_ID={user_id}",
                f"{prefix}_TOKEN={token}",
            ]
            print(f"[setup] {module}/{label} registrado: id={user_id}, username={username}")

    print("\n# Cole o bloco abaixo no seu .env:\n")
    print("\n".join(env_lines))


if __name__ == "__main__":
    main()
