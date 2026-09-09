#!/usr/bin/env python3
"""Registra 2 usuários de teste no servidor de demonstração local (demo/mock_server.py)."""
from __future__ import annotations

import base64
import secrets

import requests

BASE_URL = "http://localhost:8899"


def register(label: str) -> tuple[str, str, int, str]:
    username = f"demo{label.lower()}{secrets.token_hex(3)}"
    password = secrets.token_urlsafe(12)
    response = requests.post(f"{BASE_URL}/demo/user", json={"username": username, "password": password})
    response.raise_for_status()
    user_id = response.json()["id"]
    token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return username, password, user_id, token


def main() -> None:
    lines = []
    for label in ("A", "B"):
        username, password, user_id, token = register(label)
        prefix = f"USER_{label}_DEMO"
        lines += [
            f"{prefix}_USERNAME={username}",
            f"{prefix}_PASSWORD={password}",
            f"{prefix}_ID={user_id}",
            f"{prefix}_TOKEN={token}",
        ]
        print(f"[demo] {label} registrado: id={user_id}, username={username}")

    print("\n# Cole no .env:\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
