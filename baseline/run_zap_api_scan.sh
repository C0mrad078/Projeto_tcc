#!/usr/bin/env bash
# Roda o OWASP ZAP (zap-api-scan.py, imagem oficial zaproxy/zap-stable)
# contra o vAPI real, autenticado como o usuário USER_A_API1 (um único
# header estático global — ver zap_hooks.py), para servir de baseline
# "ferramenta de varredura tradicional" do TCC.
#
# DECISÃO DE DESIGN: usamos -O http://host.docker.internal:<porta> (com
# esquema explícito) para sobrescrever o host declarado na spec
# (localhost:8000), porque de dentro do container do ZAP "localhost" se
# refere ao próprio container, não ao host onde o vAPI está rodando via
# docker-compose. IMPORTANTE: o esquema "http://" é obrigatório aqui — sem
# ele, o zap-api-scan.py usa urllib.parse.urlparse() sobre o valor de -O, que
# interpreta "host.docker.internal" (por ter pontos) como um ESQUEMA de URL
# válido, produzindo um destino sem host real e falhando com
# "ILLEGAL_PARAMETER (url does not have a scheme.)" ao iniciar o active scan
# (bug/detalhe de implementação confirmado empiricamente rodando este script).
#
# Uso: ./baseline/run_zap_api_scan.sh
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Arquivo .env não encontrado em $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
source "$ENV_FILE"
set +a

if [[ -z "${USER_A_API1_TOKEN:-}" ]]; then
  echo "USER_A_API1_TOKEN não definido no .env — rode setup_vapi_users.py primeiro." >&2
  exit 1
fi

VAPI_HOST_PORT="${VAPI_HOST_PORT:-8000}"
WORKDIR="$PROJECT_ROOT/baseline/zap_work"
mkdir -p "$WORKDIR"
cp "$PROJECT_ROOT/specs/vapi_openapi.json" "$WORKDIR/vapi_openapi.json"
cp "$PROJECT_ROOT/baseline/zap_hooks.py" "$WORKDIR/zap_hooks.py"

DOCKER="${DOCKER_BIN:-docker}"

set +e
"$DOCKER" run --rm \
  -v "$WORKDIR:/zap/wrk:rw" \
  -e ZAP_AUTH_TOKEN="$USER_A_API1_TOKEN" \
  zaproxy/zap-stable zap-api-scan.py \
  -t /zap/wrk/vapi_openapi.json \
  -f openapi \
  -O "http://host.docker.internal:${VAPI_HOST_PORT}" \
  --hook /zap/wrk/zap_hooks.py \
  -J zap_report.json \
  -r zap_report.html \
  -I
ZAP_EXIT=$?
set -e

# Códigos de saída do zap-api-scan.py: 0=OK, 1=WARN, 2=FAIL, 3=erro interno.
# Não tratamos WARN/FAIL como falha do script — é exatamente o resultado que
# queremos capturar para a comparação do TCC.
echo
echo "zap-api-scan.py saiu com código ${ZAP_EXIT} (0=OK, 1=WARN, 2=FAIL, 3=erro interno)."
echo "Relatório salvo em ${WORKDIR}/zap_report.json e ${WORKDIR}/zap_report.html"
