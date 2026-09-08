"""
Cliente HTTP fino sobre `requests`, com registro estruturado de evidência
(requisição/resposta) para auditoria — corresponde ao item "Registro de
evidência" da metodologia do TCC: cada requisição vira um HttpExchange
serializável, que acompanha o veredito no relatório final em ./runs/.

DECISÃO DE DESIGN: o valor do cabeçalho de autenticação é parcialmente
redigido nos logs (mantemos só os 6 primeiros caracteres). Mesmo num
laboratório com credenciais descartáveis, isso vale a pena documentar como
prática — os relatórios em ./runs/ podem ser anexados ao TCC ou compartilhados
com a banca, e não há motivo para expor tokens completos neles.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from .config import Config

_session = requests.Session()


def _redact_header_value(value: str, keep: int = 6) -> str:
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "…(redacted)"


@dataclass
class HttpExchange:
    exchange_id: str
    method: str
    url: str
    request_headers: Dict[str, str]
    request_body: Optional[Any]
    status_code: Optional[int]
    response_headers: Dict[str, str]
    response_body: Optional[Any]
    latency_ms: float
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "exchange_id": self.exchange_id,
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "status_code": self.status_code,
            "response_headers": dict(self.response_headers) if self.response_headers else {},
            "response_body": self.response_body,
            "latency_ms": round(self.latency_ms, 2),
            "error": self.error,
        }


def send_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    query_params: Optional[Dict[str, str]] = None,
    json_body: Optional[dict] = None,
) -> HttpExchange:
    full_headers = {"Accept": "application/json", **headers}
    logged_headers = {
        k: (_redact_header_value(v) if k == Config.AUTH_HEADER_NAME else v)
        for k, v in full_headers.items()
    }

    start = time.monotonic()
    try:
        response = _session.request(
            method=method,
            url=url,
            headers=full_headers,
            params=query_params,
            json=json_body,
            timeout=Config.REQUEST_TIMEOUT_S,
        )
        latency_ms = (time.monotonic() - start) * 1000
        try:
            response_body: Any = response.json()
        except ValueError:
            response_body = response.text
        exchange = HttpExchange(
            exchange_id=str(uuid.uuid4()),
            method=method,
            url=url,
            request_headers=logged_headers,
            request_body=json_body,
            status_code=response.status_code,
            response_headers=dict(response.headers),
            response_body=response_body,
            latency_ms=latency_ms,
        )
    except requests.RequestException as exc:
        latency_ms = (time.monotonic() - start) * 1000
        exchange = HttpExchange(
            exchange_id=str(uuid.uuid4()),
            method=method,
            url=url,
            request_headers=logged_headers,
            request_body=json_body,
            status_code=None,
            response_headers={},
            response_body=None,
            latency_ms=latency_ms,
            error=str(exc),
        )
    finally:
        # Pequeno atraso entre requisições: o vAPI roda via `php artisan
        # serve` (servidor de desenvolvimento do Laravel, single-threaded),
        # sem tolerância a concorrência alta. Isso NÃO é uma técnica de
        # evasão de detecção — é só para não derrubar o servidor de teste local.
        if Config.REQUEST_DELAY_MS > 0:
            time.sleep(Config.REQUEST_DELAY_MS / 1000)

    return exchange
