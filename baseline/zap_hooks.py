"""
Hook customizado para o zap-api-scan.py (interface oficial de hooks do ZAP:
`--hook`, ver zap_common.py -> trigger_hook('zap_started', zap, target)).

Injeta o cabeçalho de autenticação customizado do vAPI
(Authorization-Token: base64(username:senha)) em toda requisição feita pelo
ZAP durante o scan.

DECISÃO DE DESIGN: o vAPI não usa login/sessão — é um único header estático
por identidade, validado no backend por decodificação direta (ver
agent/config.py). Por isso um Replacer global (API oficial do ZAP:
zap.replacer.add_rule, matchType=REQ_HEADER) é suficiente; não há necessidade
do mecanismo de "Authentication"/contexto de usuário do ZAP, pensado para
formulários de login ou tokens obtidos dinamicamente.

Este hook representa o mínimo de configuração necessário para o ZAP
conseguir autenticar SEQUER UMA VEZ (sem isso, todo endpoint protegido
responde 403 e o scanner não encontra nada) — ainda é um baseline "ferramenta
de varredura tradicional" porque não codifica nenhum conhecimento sobre QUAL
usuário deveria acessar QUAL recurso (isso é o que o add-on Access Control
Testing faria, usado como baseline complementar separado).

O valor do token vem da env var ZAP_AUTH_TOKEN (setada por
run_zap_api_scan.sh a partir do .env do agente) para não hardcodar
credenciais aqui.
"""
import os


def zap_started(zap, target):
    token = os.environ.get("ZAP_AUTH_TOKEN")
    if not token:
        raise RuntimeError("ZAP_AUTH_TOKEN não definida — configure antes de rodar o scan.")
    zap.replacer.add_rule(
        description="vapi-auth-token",
        enabled=True,
        matchtype="REQ_HEADER",
        matchregex=False,
        matchstring="Authorization-Token",
        replacement=token,
    )
