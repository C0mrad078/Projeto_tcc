"""
Parser de especificação OpenAPI 3.x.

DECISÃO DE DESIGN: implementamos um resolvedor de $ref minimalista (apenas
referências locais, ex.: "#/components/parameters/UserId"), em vez de usar uma
biblioteca completa de JSON Schema. A spec do vAPI usada neste TCC é pequena e
escrita à mão a partir de uma coleção Postman — não há necessidade de suportar
$ref remotos, allOf/oneOf ou schemas recursivos complexos. Um resolvedor mais
genérico seria especulativo frente ao que este projeto realmente precisa.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

PATH_PARAM_RE = re.compile(r"\{([^{}]+)\}")

HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options"}


@dataclass
class Parameter:
    name: str
    # "path" | "query" | "header" | "cookie" | "body"
    # ("body" é uma extensão nossa para representar campos de nível superior
    # do requestBody, já que a spec OpenAPI não os trata como "parameters").
    location: str
    required: bool = False
    schema_type: Optional[str] = None


@dataclass
class Endpoint:
    method: str
    path: str
    operation_id: Optional[str]
    parameters: List[Parameter] = field(default_factory=list)
    requires_auth: bool = False
    # "confirmed" | "unverified_guess" — ver campo x-confidence na spec.
    # Reflete o quanto esta parte da spec manual já foi validada contra o
    # comportamento real do vAPI (ver etapas 3-4 do roteiro do TCC).
    confidence: str = "confirmed"
    raw_operation: Dict[str, Any] = field(default_factory=dict)

    @property
    def path_params(self) -> List[Parameter]:
        return [p for p in self.parameters if p.location == "path"]

    @property
    def module(self) -> str:
        """
        Primeiro segmento do path (ex.: "api1", "api5"). No vAPI, cada módulo
        tem sua própria tabela de usuários/credenciais — completamente
        independente das demais — então este valor é usado para resolver
        qual par de identidades (A/B) usar ao gerar casos de teste para este
        endpoint (ver Config.identity() em config.py).
        """
        segments = [s for s in self.path.split("/") if s]
        return segments[0] if segments else ""

    def build_path(self, substitutions: Dict[str, str]) -> str:
        """Substitui os parâmetros de path (ex.: {api1_id}) pelos valores dados."""
        result = self.path
        for name, value in substitutions.items():
            result = result.replace("{" + name + "}", str(value))
        return result


@dataclass
class OpenAPISpec:
    base_url: str
    endpoints: List[Endpoint]
    security_schemes: Dict[str, Any]


def _resolve_ref(ref: str, document: Dict[str, Any]) -> Any:
    if not ref.startswith("#/"):
        raise ValueError(f"Apenas $ref locais são suportados; recebido: {ref}")
    node: Any = document
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def _resolve(obj: Any, document: Dict[str, Any]) -> Any:
    if isinstance(obj, dict) and "$ref" in obj:
        return _resolve(_resolve_ref(obj["$ref"], document), document)
    return obj


def _extract_base_url(document: Dict[str, Any]) -> str:
    servers = document.get("servers") or []
    if servers:
        return servers[0]["url"].rstrip("/")
    return ""


def _parse_parameters(raw_params: List[Dict[str, Any]], document: Dict[str, Any]) -> List[Parameter]:
    params = []
    for raw in raw_params:
        raw = _resolve(raw, document)
        schema = _resolve(raw.get("schema", {}), document)
        params.append(
            Parameter(
                name=raw["name"],
                location=raw.get("in", "query"),
                required=bool(raw.get("required", False)),
                schema_type=schema.get("type"),
            )
        )
    return params


def _parse_request_body_fields(
    raw_body: Optional[Dict[str, Any]], document: Dict[str, Any]
) -> List[Parameter]:
    """
    Extrai os campos de nível superior do corpo da requisição como
    Parameter(location="body").

    LIMITAÇÃO CONHECIDA: não resolvemos estruturas aninhadas (objeto dentro de
    objeto). Para os endpoints do vAPI avaliados neste trabalho, os
    identificadores de recurso relevantes para BOLA aparecem sempre no path,
    então isso é suficiente; um resolvedor recursivo completo seria
    especulativo para o escopo atual e fica registrado aqui como limitação,
    não mascarado por uma heurística frágil.
    """
    if not raw_body:
        return []
    raw_body = _resolve(raw_body, document)
    content = raw_body.get("content", {})
    json_schema = None
    for media_type in ("application/json", "application/x-www-form-urlencoded"):
        if media_type in content:
            json_schema = content[media_type].get("schema")
            break
    if not json_schema:
        return []
    json_schema = _resolve(json_schema, document)
    properties = json_schema.get("properties", {})
    required = set(json_schema.get("required", []))
    fields = []
    for name, prop_schema in properties.items():
        prop_schema = _resolve(prop_schema, document)
        fields.append(
            Parameter(
                name=name,
                location="body",
                required=name in required,
                schema_type=prop_schema.get("type"),
            )
        )
    return fields


def _find_undeclared_path_params(path: str, declared: List[Parameter]) -> List[Parameter]:
    """
    Fallback defensivo: se a spec manual esquecer de declarar um parâmetro de
    path em `parameters` (fácil de acontecer numa spec escrita à mão a partir
    de uma coleção Postman), extraímos o nome diretamente do template do path
    (ex.: "{api1_id}") e tratamos como string obrigatória por padrão.
    """
    declared_names = {p.name for p in declared if p.location == "path"}
    missing = []
    for name in PATH_PARAM_RE.findall(path):
        if name not in declared_names:
            missing.append(Parameter(name=name, location="path", required=True, schema_type="string"))
    return missing


def _endpoint_requires_auth(operation: Dict[str, Any], document: Dict[str, Any]) -> bool:
    """
    Um endpoint é considerado autenticado se tiver um `security` não-vazio,
    seja declarado na própria operação, seja herdado do nível raiz da spec.
    Um `security: []` explícito na operação sobrescreve o global e marca o
    endpoint como público (ex.: login/registro).
    """
    if "security" in operation:
        return bool(operation["security"])
    return bool(document.get("security"))


def parse_openapi(spec_path: Path) -> OpenAPISpec:
    document = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    base_url = _extract_base_url(document)
    security_schemes = (document.get("components", {}) or {}).get("securitySchemes", {})

    endpoints: List[Endpoint] = []
    for path, path_item in (document.get("paths") or {}).items():
        path_level_params = _parse_parameters(path_item.get("parameters", []), document)
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue  # ignora "parameters" e outras chaves não-HTTP do path item
            op_params = _parse_parameters(operation.get("parameters", []), document)
            body_fields = _parse_request_body_fields(operation.get("requestBody"), document)
            all_params = path_level_params + op_params + body_fields
            all_params += _find_undeclared_path_params(path, all_params)

            endpoints.append(
                Endpoint(
                    method=method.upper(),
                    path=path,
                    operation_id=operation.get("operationId"),
                    parameters=all_params,
                    requires_auth=_endpoint_requires_auth(operation, document),
                    confidence=operation.get("x-confidence", "confirmed"),
                    raw_operation=operation,
                )
            )

    return OpenAPISpec(base_url=base_url, endpoints=endpoints, security_schemes=security_schemes)
