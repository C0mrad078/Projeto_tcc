"""
Executor: percorre os TestCases gerados e realiza as chamadas HTTP reais,
trocando de identidade entre requisições (ataque cruzado).

DECISÃO DE DESIGN IMPORTANTE: o vAPI não expõe um endpoint de listagem de
recursos. Por isso este executor NUNCA tenta descobrir dinamicamente quais
recursos pertencem a qual usuário — ele usa diretamente USER_A_ID / USER_B_ID
vindos do .env (calculados por setup_vapi_users.py). Essa é uma limitação
real do ambiente de avaliação, não uma simplificação arbitrária: sem
endpoint de descoberta, não haveria como inferir outros recursos
automaticamente neste ambiente específico.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .config import Config, Identity
from .http_client import HttpExchange, send_request
from .openapi_parser import Endpoint
from .test_generator import TestCase


@dataclass
class ExecutionResult:
    test_case: TestCase
    attack_exchange: HttpExchange
    # Vítima acessando o próprio recurso — usado pelo classifier para
    # comparação diferencial de resposta (só se aplica a leituras/GET).
    baseline_exchange: Optional[HttpExchange]
    # Só para PUT/PATCH: GET pós-ataque, como a própria vítima, para checar
    # se a escrita do atacante realmente persistiu no recurso dela.
    verification_exchange: Optional[HttpExchange]


class Executor:
    def __init__(self, endpoints: List[Endpoint]) -> None:
        self._endpoints = endpoints
        # Cache de baseline por (método, path, rótulo da vítima) — evita
        # repetir a mesma requisição "de controle" quando vários casos de
        # teste reusam o mesmo endpoint de leitura.
        self._baseline_cache: Dict[Tuple[str, str, str], Optional[HttpExchange]] = {}

    def _do_request(
        self,
        method: str,
        endpoint: Endpoint,
        identity: Identity,
        path_substitutions: Dict[str, str],
        query_params: Optional[Dict[str, str]] = None,
        json_body: Optional[dict] = None,
    ) -> HttpExchange:
        url = f"{Config.TARGET_BASE_URL}{endpoint.build_path(path_substitutions)}"
        headers = Config.build_auth_header(identity.auth_token())
        return send_request(method, url, headers, query_params=query_params, json_body=json_body)

    def _find_get_counterpart(self, endpoint: Endpoint) -> Optional[Endpoint]:
        for other in self._endpoints:
            if other.path == endpoint.path and other.method == "GET":
                return other
        return None

    def _get_baseline(self, test_case: TestCase) -> Optional[HttpExchange]:
        endpoint = test_case.endpoint
        if endpoint.method != "GET":
            # Para PUT/PATCH, o que importa é a verificação pós-ataque, não
            # uma leitura prévia — ver `_get_verification`.
            return None
        cache_key = (endpoint.method, endpoint.path, test_case.victim.label)
        if cache_key not in self._baseline_cache:
            own_substitutions = {p.name: test_case.victim.resource_id for p in endpoint.path_params}
            # BUG REAL ENCONTRADO E CORRIGIDO (exercício do caso ambíguo de
            # demonstração, demo/mock_server.py): quando o parâmetro
            # candidato mora em query (não em path), o baseline sem
            # `query_params` saía incompleto — o servidor recusava a
            # requisição (ex.: "report_id é obrigatório"), mascarando a
            # comparação diferencial do classifier. `test_case.query_params`
            # já é montado por test_generator.py com o ID da VÍTIMA como
            # valor (usado no ataque); reaproveitá-lo aqui, com o token da
            # própria vítima, é exatamente a requisição "dona acessando o
            # próprio recurso" que o baseline precisa.
            self._baseline_cache[cache_key] = self._do_request(
                "GET", endpoint, test_case.victim, own_substitutions,
                query_params=test_case.query_params or None,
            )
        return self._baseline_cache[cache_key]

    def _get_verification(self, test_case: TestCase) -> Optional[HttpExchange]:
        """
        Depois de um ataque de escrita, faz um GET como a PRÓPRIA vítima para
        conferir se o valor "canário" injetado pelo atacante persistiu no
        recurso dela. Sem isso, um status 200 de um PUT não prova exploração
        — várias APIs retornam 200 mesmo em escritas que falham silenciosamente.
        """
        if test_case.endpoint.method not in {"PUT", "PATCH"}:
            return None
        get_endpoint = self._find_get_counterpart(test_case.endpoint)
        if get_endpoint is None:
            return None
        own_substitutions = {p.name: test_case.victim.resource_id for p in get_endpoint.path_params}
        # Mesma correção aplicada em `_get_baseline`: se o identificador do
        # recurso mora em query (não em path), a verificação também precisa
        # desse parâmetro — assume que o GET homólogo usa o mesmo nome/local
        # de parâmetro que o candidato original (mesma suposição já feita
        # por `_find_get_counterpart`, que casa só por path).
        return self._do_request(
            "GET", get_endpoint, test_case.victim, own_substitutions,
            query_params=test_case.query_params or None,
        )

    def run(self, test_case: TestCase) -> ExecutionResult:
        baseline = self._get_baseline(test_case)

        attack_exchange = self._do_request(
            test_case.endpoint.method,
            test_case.endpoint,
            test_case.attacker,
            test_case.path_substitutions,
            query_params=test_case.query_params or None,
            json_body=test_case.body,
        )

        verification = self._get_verification(test_case)

        return ExecutionResult(
            test_case=test_case,
            attack_exchange=attack_exchange,
            baseline_exchange=baseline,
            verification_exchange=verification,
        )

    def run_all(self, test_cases: List[TestCase]) -> List[ExecutionResult]:
        return [self.run(tc) for tc in test_cases]
