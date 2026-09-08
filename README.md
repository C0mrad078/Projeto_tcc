# Agente LLM para Detecção de BOLA em APIs REST via OpenAPI

Protótipo de TCC: um agente que lê a especificação OpenAPI de uma API REST, infere quais parâmetros identificam recursos pertencentes a um usuário específico, gera e executa casos de teste cruzados de **BOLA** (Broken Object Level Authorization — API1 do OWASP API Security Top 10), classifica os resultados e compara o desempenho com uma ferramenta de varredura tradicional (OWASP ZAP).

**Pergunta de pesquisa:** em que medida o uso da especificação OpenAPI como fonte estruturada de reconhecimento melhora a precisão e a revocação de um agente baseado em LLM na detecção de BOLA, em comparação a uma ferramenta de varredura tradicional?

> ⚠️ **Escopo de uso.** Este código foi construído para um único alvo: uma instância **local** do [vAPI](https://github.com/roottusk/vapi) (ambiente vulnerável por design, para fins educacionais). Não aponte este agente para qualquer sistema que você não tenha autorização explícita para testar.

---

## Sumário

- [Arquitetura](#arquitetura)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Subindo o vAPI](#subindo-o-vapi)
- [Registrando usuários de teste](#registrando-usuários-de-teste)
- [Rodando o agente](#rodando-o-agente)
- [Lendo o relatório](#lendo-o-relatório)
- [Ground truth e métricas](#ground-truth-e-métricas)
- [Baseline com OWASP ZAP](#baseline-com-owasp-zap)
- [Estrutura do repositório](#estrutura-do-repositório)
- [Achados e limitações conhecidas](#achados-e-limitações-conhecidas)

---

## Arquitetura

```
specs/vapi_openapi.json
        │
        ▼
openapi_parser.py        → normaliza endpoints, parâmetros e requisitos de auth
        │
        ▼
relation_inference.py    → heurística (+ LLM opcional) acha parâmetros candidatos a
        │                   identificar um recurso de usuário específico
        ▼
test_generator.py        → gera casos cruzados: B ataca o recurso de A, A ataca o de B
        │
        ▼
executor.py + http_client.py → executa as requisições reais contra o alvo
        │                        (baseline → ataque → verificação pós-escrita)
        ▼
classifier.py             → heurística (+ LLM como desempate) decide o veredito
        │
        ▼
orchestrator.py           → junta tudo, grava o relatório em ./runs/*.json
        │
        ▼
compute_metrics.py        → compara com ground_truth/*.json → precisão/revocação/F1
```

Cada estágio é um módulo independente em `agent/`, testável isoladamente. O LLM (Google Gemini, via Google AI Studio) só é chamado quando a heurística não tem confiança suficiente — nos endpoints do vAPI avaliados, isso nunca acontece, e o pipeline inteiro roda 100% determinístico.

### Por que o LLM entra em dois lugares diferentes

- **`relation_inference.py`**: desempate para decidir se um parâmetro (ex.: `category`, `order_id`) provavelmente identifica um recurso de um usuário específico.
- **`classifier.py`**: desempate para decidir, a partir da requisição/resposta real, se um caso ambíguo (ex.: HTTP 404 sem baseline claro) é uma falha confirmada, uma proteção correta, ou permanece ambíguo.

Em ambos os casos, a heurística resolve os casos óbvios sozinha — o LLM só entra no caminho quando a heurística não decide, o que mantém custo baixo e os resultados reprodutíveis.

---

## Requisitos

- Python 3.10+
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (para o vAPI e, opcionalmente, o baseline ZAP)
- Uma chave de API do [Google AI Studio](https://aistudio.google.com/apikey) (opcional — só necessária se você quiser o desempate por LLM; o pipeline funciona sem ela, com `--no-llm` ou deixando os casos ambíguos marcados para revisão manual)

## Instalação

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Preencha `GOOGLE_API_KEY` no `.env` se for usar o desempate por LLM. As variáveis `USER_*_API1_*` / `USER_*_API5_*` são preenchidas automaticamente mais adiante, por `setup_vapi_users.py`.

---

## Subindo o vAPI

O vAPI não faz parte deste repositório — é um projeto externo (Laravel + MySQL) que precisa ser clonado à parte:

```bash
git clone https://github.com/roottusk/vapi.git ../vapi   # ou onde preferir
cd ../vapi
docker compose up -d
```

Isso sobe três containers: a aplicação Laravel (`www`), o MySQL (`db`) e um phpMyAdmin opcional. **A porta real é `8000` no host** (mapeada para a porta 80 do container, onde o `php artisan serve` escuta — o `docker-compose.yml` do próprio vAPI já resolve isso via a env var `SERVER_PORT=80`).

Valide que subiu:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/vapi/
# esperado: 200
```

`TARGET_BASE_URL` no `.env` já vem configurado para `http://localhost:8000/vapi` por padrão.

---

## Registrando usuários de teste

```bash
python setup_vapi_users.py
```

Isso registra **4 contas** — usuários A e B, cada um nos módulos API1 e API5 (que têm tabelas de usuários completamente independentes no vAPI, sem nenhuma relação entre si) — e imprime um bloco pronto para colar no `.env`:

```
USER_A_API1_USERNAME=...
USER_A_API1_PASSWORD=...
USER_A_API1_ID=...
USER_A_API1_TOKEN=...
USER_B_API1_USERNAME=...
...
USER_A_API5_USERNAME=...
...
USER_B_API5_USERNAME=...
...
```

Não existe endpoint de login no vAPI — o token é só `base64(username:senha)`, calculado pelo próprio script e enviado no cabeçalho customizado `Authorization-Token` em toda requisição autenticada.

---

## Rodando o agente

```bash
# Só parser + inferência + geração de casos, sem nenhuma chamada de rede real:
python main.py --dry-run

# Execução completa contra o vAPI real:
python main.py

# Forçar modo 100% heurístico, sem nenhuma chamada ao Gemini:
python main.py --no-llm

# Especificar outra spec:
python main.py --spec caminho/para/outra_spec.json
```

Para o vAPI, a spec atual tem 3 operações autenticadas com parâmetro de ID (`GET`/`PUT /api1/user/{api1_id}` e `GET /api5/user/{api5_id}`); cada uma vira 2 casos cruzados (B ataca A, A ataca B), totalizando **6 casos de teste**. Na avaliação atual, os 6 são resolvidos só com a heurística — sem precisar do LLM.

---

## Lendo o relatório

Cada execução real grava um JSON em `./runs/run_<uuid>.json`, com:

- `candidates`: os parâmetros que a inferência de relações identificou como candidatos a BOLA, com origem (`heuristic` ou `llm`) e justificativa.
- `results`: um item por caso de teste, com o veredito (`confirmed` / `not_found` / `ambiguous`), a razão, e as três trocas HTTP completas (`attack_exchange`, `baseline_exchange`, `verification_exchange`) — requisição, resposta, status, latência. O valor do cabeçalho de autenticação vem parcialmente redigido (só os 6 primeiros caracteres) mesmo sendo um laboratório descartável.

---

## Ground truth e métricas

`ground_truth/vapi.json` documenta as falhas de BOLA confirmadas por leitura direta do código-fonte dos controllers Laravel do vAPI (não por suposição):

- **`GET`/`PUT /api1/user/{api1_id}`** — confirmadas, nas duas direções. O controller (`API1UsersController`) valida usuário/senha mas nunca compara o `id` autenticado com o `{api1_id}` pedido.
- **`GET /api5/user/{api5_id}`** — **não é uma falha de BOLA.** `API5UsersController::show` inclui `->where('id', $id)` na query, ou seja, verifica corretamente a posse do recurso. A falha real do módulo API5 é `GET /api5/users` (listagem completa sem parâmetro de ID, acessível a qualquer usuário autenticado) — isso é *Broken Function Level Authorization* (API5:2019), não BOLA por objeto, e fica fora do escopo de candidatos deste agente por definição (não tem parâmetro de ID para testar).

```bash
python compute_metrics.py --run runs/run_<uuid>.json --ground-truth ground_truth/vapi.json
```

**Resultado em 5 execuções reais consecutivas contra o vAPI:** Precisão = Revocação = F1 = **1.000**, desvio padrão = 0 em todas — porque os 6 vereditos são decididos inteiramente pela heurística determinística, sem nenhum caso ambíguo acionando o LLM neste ambiente.

---

## Baseline com OWASP ZAP

```bash
./baseline/run_zap_api_scan.sh
```

Sobe o container oficial `zaproxy/zap-stable` e roda `zap-api-scan.py` contra o vAPI real, importando `specs/vapi_openapi.json` e autenticado como **um único usuário** (header estático injetado via `baseline/zap_hooks.py`, usando a API oficial `zap.replacer.add_rule` — o vAPI não tem login/sessão, então isso é suficiente). Representa a "ferramenta de varredura tradicional" da pergunta de pesquisa: nenhum conhecimento sobre qual usuário deveria acessar qual recurso é codificado, só o mínimo para autenticar.

**Resultado real:** 13 tipos de alerta, todos de higiene genérica de segurança (headers ausentes, vazamento de erro 500, `X-Powered-By`) — **zero relacionados a BOLA/IDOR**. Isso é esperado: o ZAP não tem noção semântica de "comparar acesso entre duas identidades autenticadas diferentes" sem configuração adicional (ex.: o add-on Access Control Testing, ainda não integrado neste repositório).

| | Precisão | Revocação | F1 |
|---|---|---|---|
| ZAP (out-of-the-box) | — (0 positivos) | 0/4 = 0.0 | 0.0 |
| Agente (5 execuções) | 1.0 | 1.0 | 1.0 |

Relatórios (`zap_report.json`/`.html`) ficam em `baseline/zap_work/` (não versionado — regenerável rodando o script de novo).

---

## Estrutura do repositório

```
agent/
  config.py              Configuração (.env), identidades por módulo
  openapi_parser.py       Parser de OpenAPI 3.x (resolvedor de $ref minimalista)
  relation_inference.py   Heurística + LLM: acha candidatos a BOLA
  test_generator.py       Gera os casos de teste cruzados A↔B
  http_client.py          Cliente HTTP com log estruturado de evidência
  executor.py              Executa os casos contra o alvo real
  classifier.py            Decide o veredito (heurística + LLM de desempate)
  orchestrator.py           Junta tudo, grava o relatório em ./runs/
  metrics.py                Precisão/revocação/F1 contra o ground truth
specs/
  vapi_openapi.json         Spec OpenAPI do vAPI (reconstruída e corrigida manualmente)
ground_truth/
  vapi.json                 Gabarito manual (validado por leitura de código-fonte)
baseline/
  run_zap_api_scan.sh        Script do baseline OWASP ZAP
  zap_hooks.py                Hook de autenticação para o ZAP
main.py                       CLI do pipeline
setup_vapi_users.py            Registra usuários de teste no vAPI real
compute_metrics.py              CLI de métricas
runs/                            Relatórios de execução (gitignored)
```

---

## Achados e limitações conhecidas

Registrados aqui porque viram material direto para a seção de "ameaças à validade" do TCC:

- **Sem endpoint de listagem**: o vAPI não expõe descoberta dinâmica de recursos, então o agente usa sempre o próprio perfil do usuário de teste (IDs conhecidos via `.env`) como "recurso conhecido" — não generaliza para recursos subordinados (ex.: pedidos de um usuário) sem uma fonte adicional de identificadores.
- **Identidades por módulo**: APIs cujos módulos têm bases de usuários completamente independentes (como API1 e API5 do vAPI) exigem credenciais/IDs próprios por módulo — não um par de identidades global. `Config.identity(module, label)` resolve isso; um alvo hipotético com uma única base de usuários compartilhada entre todos os endpoints precisaria de uma simplificação equivalente.
- **Path com múltiplos parâmetros**: quando um endpoint tem mais de um parâmetro de path, o gerador de casos substitui todos pelo ID da vítima — correto para os endpoints do vAPI avaliados (um parâmetro cada), mas incorreto para um endpoint hipotético como `/users/{user_id}/orders/{order_id}`, onde só um deveria variar.
- **Auth header vs. spec OpenAPI padrão**: a autenticação do vAPI (header customizado com `base64(usuario:senha)`, sem OAuth/login) não é modelada nativamente por `securitySchemes` do OpenAPI — é tratada via configuração explícita (`AUTH_HEADER_NAME`/`AUTH_HEADER_FORMAT`), não descoberta automaticamente a partir da spec.
- **Não generaliza para RPC-style (ex.: Server Actions do Next.js)**: o agente pressupõe uma API REST com endpoints, métodos HTTP e parâmetros fixos, documentável via OpenAPI. Frameworks full-stack modernos que expõem a lógica de negócio via chamadas RPC internas (ex.: Next.js Server Actions) não têm essa superfície — testado em um projeto real durante o desenvolvimento deste TCC, confirmando a incompatibilidade arquitetural.
- **Probe de escrita e campos de credencial**: a primeira versão do probe de PUT preenchia todos os campos do corpo com um valor canário, incluindo `username`/`password` — sobrescrevendo as credenciais da própria vítima durante o ataque. Corrigido excluindo campos com cara de credencial (`CREDENTIAL_LIKE_FIELD_NAMES` em `test_generator.py`).
