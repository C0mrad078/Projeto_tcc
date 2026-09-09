#!/usr/bin/env python3
"""
Servidor HTTP mínimo, local e propositalmente vulnerável a BOLA — usado SÓ
para demonstrar o modo "hybrid" decidindo um caso GENUINAMENTE AMBÍGUO com
uma chamada real ao LLM. Não faz parte da avaliação do vAPI: não entra em
ground_truth/vapi.json, não conta para as métricas do TCC, não é o "segundo
ambiente" do próximo passo da refatoração (esse ainda está pendente).

POR QUE UM CASO AMBÍGUO DE VERDADE, NÃO FABRICADO: nenhum endpoint do vAPI
tem um parâmetro na faixa ambígua de relation_inference.py, nem uma resposta
que escape das regras de correspondência de classifier.py (achado
documentado no README, seção "Modos experimentais" — o modo "hybrid" nunca
precisou decidir nada de verdade contra o vAPI). Este servidor existe para
provar que o CAMINHO DE CÓDIGO do modo "hybrid" funciona ponta a ponta
quando a ambiguidade genuinamente ocorre.

A ambiguidade é uma CONSEQUÊNCIA REAL deste design, não uma alegação:
  - GET /demo/report?report_id=<id>: "report_id" está em query + GET
    -> score = LOCATION_WEIGHT["query"] (0.5) * METHOD_WEIGHT["GET"] (1.0)
    = 0.5, entre REJECT_THRESHOLD (0.3) e CONFIRM_THRESHOLD (0.7) — a
    heurística de relation_inference.py genuinamente não confirma nem
    rejeita esse parâmetro sozinha.
  - O corpo da resposta NUNCA contém o ID numérico da vítima em texto puro
    (só um "owner_note" com o USERNAME dela) — então
    classifier._body_contains(body, victim_id) nunca confirma.
  - O corpo inclui "generated_at" (timestamp real da requisição), então
    nunca é byte-a-byte idêntico ao baseline — então
    classifier._bodies_match() também nunca confirma.
  - O endpoint É de fato vulnerável (nenhuma verificação de posse do
    relatório pedido) — a resposta correta, semanticamente, é "confirmed",
    só alcançável aqui via julgamento do LLM.
"""
from __future__ import annotations

import base64
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

USERS: dict = {}  # username -> {"id": int, "password": str}
REPORTS: dict = {}  # id -> {"username": str, "note": str}
_next_id = [1]


def _authenticate(headers) -> dict | None:
    token = headers.get("Authorization-Token")
    if not token:
        return None
    try:
        decoded = base64.b64decode(token).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception:
        return None
    user = USERS.get(username)
    if user and user["password"] == password:
        return user
    return None


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802 (nome exigido pela BaseHTTPRequestHandler)
        parsed = urlparse(self.path)
        if parsed.path == "/demo/user":
            length = int(self.headers.get("Content-Length", 0))
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"error": "corpo inválido"})
            username, password = data.get("username"), data.get("password")
            if not username or not password or username in USERS:
                return self._send(400, {"error": "username/password inválidos ou já existentes"})
            user_id = _next_id[0]
            _next_id[0] += 1
            USERS[username] = {"id": user_id, "password": password}
            REPORTS[user_id] = {"username": username, "note": f"Relatório confidencial de {username}"}
            return self._send(200, {"id": user_id, "username": username})
        return self._send(404, {"error": "not found"})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/demo/report":
            user = _authenticate(self.headers)
            if user is None:
                return self._send(403, {"error": "authHeaderNotSetOrInvalid"})
            report_id_values = parse_qs(parsed.query).get("report_id")
            if not report_id_values:
                return self._send(400, {"error": "report_id é obrigatório"})
            try:
                report_id = int(report_id_values[0])
            except ValueError:
                return self._send(400, {"error": "report_id inválido"})
            report = REPORTS.get(report_id)
            if report is None:
                return self._send(404, {"error": "relatório não encontrado"})
            # VULNERÁVEL DE PROPÓSITO: nenhuma verificação de que report_id
            # pertence ao usuário autenticado (`user`) — é exatamente o que
            # este servidor de demonstração existe para expor.
            return self._send(
                200,
                {
                    "report_ref": f"RPT-{report_id:03d}",
                    "owner_note": report["note"],
                    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
            )
        return self._send(404, {"error": "not found"})

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass  # a evidência já vem do relatório do agente; silencia o log padrão


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    server = HTTPServer(("localhost", port), Handler)
    print(f"[demo] Servidor de demonstração (propositalmente vulnerável) em http://localhost:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
