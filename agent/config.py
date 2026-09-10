"""
Configuração centralizada do agente.

Toda credencial e URL de alvo vem de variáveis de ambiente (.env) — nunca
hardcoded — justamente para reduzir o risco de este código, escrito para um
laboratório vulnerável por design (vAPI), ser reaproveitado sem querer contra
qualquer outro alvo.

Os atributos de classe abaixo (URLs, nomes de cabeçalho, flags) têm defaults
seguros e podem ser lidos mesmo sem um .env completo — isso é o que permite
rodar o parser/inferência/geração de casos offline (--dry-run) sem qualquer
configuração de rede. Já os métodos `identity()` / `require_network_config()`
são explicitamente carregados sob demanda pelas etapas que realmente
precisam de credenciais (executor.py via orchestrator.py, setup_vapi_users.py),
para que a ausência delas só quebre quem depende delas.

DECISÃO DE DESIGN IMPORTANTE (achado ao inspecionar o código-fonte real do
vAPI): cada módulo do vAPI (api1, api5, ...) tem sua PRÓPRIA tabela de
usuários no MySQL (`a_p_i1_users`, `a_p_i5_users`, ...), com contadores de ID
independentes e nenhuma relação entre si. Não existe um "Usuário A" único
compartilhado entre módulos — é preciso registrar (e guardar credenciais/ID)
separadamente por módulo. Por isso as identidades aqui são resolvidas por
`(módulo, rótulo)` em vez de um par fixo `user_a()`/`user_b()` global, que foi
a modelagem inicial (incorreta) deste agente antes dessa descoberta.
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Literal, Optional

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent

Mode = Literal["heuristic", "hybrid", "llm"]
VALID_MODES: tuple = ("heuristic", "hybrid", "llm")


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


def _env_mode(name: str, default: Mode) -> Mode:
    """
    Lê um dos três modos experimentais (Fase 6 da refatoração metodológica):
    "heuristic" (LLM nunca chamado), "hybrid" (default — heurística primeiro,
    LLM só em ambiguidade) ou "llm" (experimental: força avaliação por LLM
    mesmo onde a heurística já decidiria sozinha, para permitir estudo de
    ablação). Um valor inválido no .env não derruba o programa — cai no
    default "hybrid" com um aviso, já que travar por uma variável de
    configuração mal escrita seria pior do que seguir com o comportamento
    recomendado.
    """
    value = os.environ.get(name)
    if value is None:
        return default
    value = value.strip().lower()
    if value not in VALID_MODES:
        print(
            f"[config] Aviso: {name}='{value}' inválido (esperado um de {VALID_MODES}); "
            f"usando '{default}'."
        )
        return default
    return value  # type: ignore[return-value]


@dataclass(frozen=True)
class Identity:
    """
    Um usuário de teste (A ou B) em UM módulo específico do vAPI (ex.: "A no
    módulo api1" e "A no módulo api5" são duas contas completamente
    independentes, com IDs e credenciais próprias).
    """

    label: str
    username: Optional[str]
    password: Optional[str]
    resource_id: Optional[str]
    token: Optional[str] = None

    def auth_token(self) -> str:
        """
        Retorna o token pronto para o cabeçalho de autenticação.

        Se USER_{label}_{módulo}_TOKEN já estiver definido no .env, usamos
        ele diretamente — é o que setup_vapi_users.py grava depois de
        registrar os usuários reais. Caso contrário, calculamos
        base64(username:senha) on-the-fly, útil para configurar um cenário de
        teste manual sem depender do script de setup.
        """
        if self.token:
            return self.token
        if self.username is None or self.password is None:
            raise ValueError(
                f"Identidade '{self.label}' não tem token nem username/senha configurados."
            )
        raw = f"{self.username}:{self.password}".encode("utf-8")
        return base64.b64encode(raw).decode("ascii")


class Config:
    # --- Alvo ---
    # DECISÃO DE DESIGN: o docker-compose.yml oficial do vAPI mapeia a porta
    # 8000 do host para a porta 80 do container (onde o `php artisan serve`
    # efetivamente escuta, via a env var SERVER_PORT=80 do próprio compose).
    # Ou seja, o vAPI rodando via Docker fica em localhost:8000, não em
    # localhost:80 — confirmado empiricamente subindo o container.
    TARGET_BASE_URL: str = _env("TARGET_BASE_URL", "http://localhost:8000/vapi")
    REQUEST_TIMEOUT_S: float = _env_float("REQUEST_TIMEOUT_S", 10.0)
    REQUEST_DELAY_MS: float = _env_float("REQUEST_DELAY_MS", 150.0)

    # --- Autenticação dos módulos do vAPI ---
    # DECISÃO DE DESIGN: o vAPI não usa "Authorization: Bearer <token>" como a
    # maioria das specs OpenAPI de exemplo assume — ele usa um cabeçalho
    # customizado contendo base64(usuario:senha), validado no backend
    # decodificando o header e comparando contra a tabela do módulo (ver
    # app/CustomClasses/CustomHeaderAuth.php e os controllers API1/API5 no
    # código-fonte do vAPI). Isso é parametrizado aqui (em vez de fixo em
    # http_client.py/executor.py) para que, se este agente for reaproveitado
    # contra outro alvo do mesmo TCC com esquema de auth diferente, baste
    # trocar estas duas variáveis.
    AUTH_HEADER_NAME: str = _env("AUTH_HEADER_NAME", "Authorization-Token")
    AUTH_HEADER_FORMAT: str = _env("AUTH_HEADER_FORMAT", "{token}")

    # --- Especificação ---
    OPENAPI_SPEC_PATH: Path = Path(
        _env("OPENAPI_SPEC_PATH", str(PROJECT_ROOT / "specs" / "vapi_openapi.json"))
    )

    # --- LLM (Google AI Studio / Gemini API) ---
    # DECISÃO DE DESIGN: o SDK oficial (google-genai) já lê GOOGLE_API_KEY ou
    # GEMINI_API_KEY sozinho do ambiente; guardamos o valor aqui só para
    # decidir, de forma explícita, se devemos sequer tentar uma chamada de
    # LLM (ver relation_inference.py/classifier.py) — não para repassá-lo
    # manualmente ao cliente em todo lugar.
    GOOGLE_API_KEY: Optional[str] = _env("GOOGLE_API_KEY") or _env("GEMINI_API_KEY")
    LLM_MODEL: str = _env("LLM_MODEL", "gemini-3.8-flash")

    # --- Modo experimental (Fase 6 da refatoração metodológica) ---
    # DECISÃO DE DESIGN: MODE é a interface recomendada — controla os dois
    # pontos de decisão (relation_inference e classifier) de forma
    # consistente. "hybrid" é o modo padrão e o único recomendado para o TCC
    # em si; "heuristic" e "llm" existem para permitir, no futuro, um estudo
    # de ablação (Heurística vs. Híbrido vs. LLM vs. ZAP) sem reescrever o
    # agente — ver README, seção "Modos experimentais".
    MODE: Mode = _env_mode("AGENT_MODE", "hybrid")

    # Mantidos por compatibilidade com quem já configurou o .env antes do
    # conceito de MODE existir (ver commit da Fase 6): quando ausentes do
    # .env, são DERIVADOS de MODE; quando presentes, sobrescrevem MODE só
    # para o ponto de decisão correspondente (uso avançado/depuração — o
    # caminho recomendado é usar MODE ou --mode).
    USE_LLM_FOR_RELATION_INFERENCE: bool = _env_bool(
        "USE_LLM_FOR_RELATION_INFERENCE", MODE != "heuristic"
    )
    USE_LLM_FOR_CLASSIFICATION: bool = _env_bool(
        "USE_LLM_FOR_CLASSIFICATION", MODE != "heuristic"
    )
    # INCIDENTE REAL: numa rodada contra o vAPI real, uma chamada ao Gemini
    # ficou pendurada indefinidamente (sem essa configuração, o SDK usa seu
    # próprio timeout padrão, que não é garantidamente curto), travando o
    # pipeline inteiro sem nenhum log. Definimos um teto explícito para que
    # uma falha de rede vire uma exceção tratável (ver o `except Exception`
    # em relation_inference.py/classifier.py) em vez de um travamento silencioso.
    LLM_TIMEOUT_S: float = _env_float("LLM_TIMEOUT_S", 30.0)

    # --- Saída ---
    RUNS_DIR: Path = Path(_env("RUNS_DIR", str(PROJECT_ROOT / "runs")))

    # --- Generalização (Fase 8 da refatoração metodológica) ---
    # "per_module" (default) preserva o comportamento validado do vAPI —
    # cada módulo (api1, api5, ...) tem sua própria tabela de usuários.
    # "shared" é para um alvo hipotético com UMA base de usuários
    # compartilhada entre todos os endpoints — ver agent/adapters.py.
    IDENTITY_STRATEGY: str = _env("IDENTITY_STRATEGY", "per_module")

    @staticmethod
    def build_auth_header(token: str) -> dict:
        """Monta o cabeçalho HTTP de autenticação a partir do token bruto."""
        header_value = Config.AUTH_HEADER_FORMAT.format(token=token)
        return {Config.AUTH_HEADER_NAME: header_value}

    @staticmethod
    def identity(module: str, label: str) -> Identity:
        """
        Carrega a identidade `label` ("A" ou "B") para o módulo `module`
        (ex.: "api1", "api5"). Delega para o IdentityProvider escolhido por
        IDENTITY_STRATEGY (ver agent/adapters.py) — o default "per_module"
        é bit-a-bit idêntico ao comportamento original (variáveis como
        USER_A_API1_USERNAME / USER_A_API1_PASSWORD / USER_A_API1_ID /
        USER_A_API1_TOKEN), só extraído para uma classe própria para permitir
        outras estratégias sem tocar neste método.
        """
        from .adapters import build_identity_provider  # import tardio: evita ciclo (adapters usa Identity daqui)

        return build_identity_provider(Config.IDENTITY_STRATEGY).get(module, label)

    @staticmethod
    def require_network_config(modules: List[str]) -> None:
        """
        Valida a configuração mínima para etapas que fazem chamadas HTTP
        reais (executor.py via orchestrator.py, setup_vapi_users.py).
        Chamado explicitamente por essas etapas — nunca no import do módulo
        — para que o uso só-offline (parser/inferência/geração de casos) não
        exija um .env completo.

        `modules` é a lista de módulos (ex.: ["api1", "api5"]) realmente
        envolvidos nos casos de teste gerados nesta execução — só exigimos
        credenciais para os módulos que serão de fato usados.
        """
        missing: List[str] = []
        for module in modules:
            for label in ("A", "B"):
                ident = Config.identity(module, label)
                prefix = f"USER_{label}_{module.upper()}"
                if not ident.resource_id:
                    missing.append(f"{prefix}_ID")
                try:
                    ident.auth_token()
                except ValueError:
                    missing.append(f"{prefix}_TOKEN ou {prefix}_USERNAME/PASSWORD")
        if missing:
            raise RuntimeError(
                "Configuração incompleta para execução contra o vAPI real. "
                f"Faltando: {', '.join(missing)}. Rode setup_vapi_users.py "
                "primeiro ou preencha o .env manualmente."
            )
