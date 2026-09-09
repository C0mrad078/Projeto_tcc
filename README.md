# Agente Híbrido para Detecção de BOLA via OpenAPI

## Projeto

Agente híbrido para detecção automatizada de **BOLA — Broken Object Level Authorization (OWASP API1:2023)** em APIs REST, guiado por especificação OpenAPI.

> ⚠️ **Escopo de uso.** Este código foi construído e validado contra uma instância **local** do [vAPI](https://github.com/roottusk/vapi) (ambiente vulnerável por design, para fins educacionais). Não aponte este agente para qualquer sistema que você não tenha autorização explícita para testar — ver [Escolhendo o alvo](#escolhendo-o-alvo).

**Escopo oficial: BOLA / API1:2023.** Este projeto não é (e não tenta ser) um scanner do OWASP API Security Top 10 inteiro — não cobre BFLA, Broken Authentication, Excessive Data Exposure, etc. Onde uma dessas outras categorias apareceu incidentalmente durante o desenvolvimento (ver `GET /api5/users` nas [Limitações](#limitações-conhecidas)), ela foi documentada como fora de escopo, não implementada.

## Problema

BOLA depende de uma relação de autorização entre um usuário e um recurso — "este objeto pertence a este usuário" — que não é visível a partir de uma única requisição isolada. Um scanner tradicional, autenticado como um único usuário, não tem como saber que `GET /pedido/123` deveria ser negado quando quem pede não é o dono do pedido 123: ele só vê "uma URL, uma resposta", nunca a comparação entre duas identidades sobre o mesmo recurso que é exatamente o que caracteriza a falha.

## Proposta

**OpenAPI como fonte estruturada de reconhecimento** (paths, parâmetros, requisitos de autenticação) + **duas identidades de teste autenticadas** (Usuário A e Usuário B) + **geração automática de ataques cruzados** (A tentando acessar/alterar o recurso de B, e vice-versa) + **arquitetura híbrida de decisão**: heurísticas determinísticas resolvem os casos claros, e um LLM (Google Gemini) entra apenas onde há ambiguidade semântica real.

**Pergunta de pesquisa:** em que medida o uso da especificação OpenAPI como fonte estruturada de reconhecimento melhora a precisão e a revocação de um agente híbrido na detecção de BOLA, em comparação a uma ferramenta de varredura tradicional?

---

## Sumário

- [Arquitetura híbrida](#arquitetura-híbrida)
- [Pipeline](#pipeline)
- [Modos experimentais](#modos-experimentais)
- [Rastreabilidade de decisão e telemetria de LLM](#rastreabilidade-de-decisão-e-telemetria-de-llm)
- [Requisitos e instalação](#requisitos-e-instalação)
- [Subindo o vAPI](#subindo-o-vapi)
- [Registrando usuários de teste](#registrando-usuários-de-teste)
- [Escolhendo o alvo](#escolhendo-o-alvo)
- [Rodando o agente](#rodando-o-agente)
- [Formato do relatório](#formato-do-relatório)
- [Ground truth e métricas](#ground-truth-e-métricas)
- [Baseline com OWASP ZAP](#baseline-com-owasp-zap)
- [Testes automatizados](#testes-automatizados)
- [Estrutura do repositório](#estrutura-do-repositório)
- [Sobre a especificação OpenAPI](#sobre-a-especificação-openapi)
- [Limitações conhecidas](#limitações-conhecidas)
- [Ameaças à validade](#ameaças-à-validade)
- [Próximos passos](#próximos-passos)

---

## Arquitetura híbrida

Dois níveis de decisão, sempre nesta ordem de prioridade, nos dois pontos do pipeline onde o agente decide algo (`agent/relation_inference.py` e `agent/classifier.py`):

**Nível 1 — Heurística (determinística, sem custo de API).** Regras explícitas: nome/localização de parâmetro para achar candidatos a identificador de objeto; status HTTP 401/403 para negação; corpo da resposta idêntico ao baseline da vítima, ou contendo o identificador dela, para confirmação; persistência do valor "canário" numa escrita para provar exploração real. Decide sozinha sempre que há confiança suficiente.

**Nível 2 — LLM (Google Gemini via Google AI Studio).** Só é chamado quando a heurística **não tem confiança suficiente** — um score de candidato na faixa ambígua, ou um veredito de classificação `ambiguous`. Nunca é o primeiro a decidir no modo recomendado (`hybrid`).

Toda decisão relevante carrega uma `Decision` (`agent/decision.py`) registrando explicitamente qual mecanismo decidiu:

```python
@dataclass
class Decision:
    decision_source: Literal["heuristic", "llm", "hybrid"]
    reason: str
    confidence: Optional[float]  # None quando não há como calcular — nunca inventado
    model: Optional[str] = None
    duration_ms: Optional[float] = None
```

`"hybrid"` é usado quando a heurística já produziu um sinal (candidato ambíguo, veredito ambíguo) e o LLM desempatou esse sinal — nem heurística pura, nem LLM decidindo do zero. `"llm"` puro só acontece no modo experimental `llm` (ver abaixo), onde o LLM substitui a heurística mesmo em casos que ela já resolveria.

## Pipeline

```
OpenAPI spec
     │
     ▼
openapi_parser.py  ──  endpoints, parâmetros, requisitos de auth
     │
     ▼
relation_inference.py  ──  candidatos a identificador de objeto
     │                          │
     │                     heurística confiante? ──sim──▶ decision_source=heuristic
     │                          │ não
     │                          ▼
     │                     modo permite LLM? ──sim──▶ LLM desempata ──▶ decision_source=hybrid (ou llm, no modo llm)
     │                          │ não (modo heuristic)
     │                          ▼
     │                     candidato descartado
     ▼
test_generator.py  ──  Identity A/B  ──  ataques cruzados A→B, B→A
     │
     ▼
executor.py + http_client.py  ──  baseline → ataque → verificação pós-escrita (requisições HTTP reais)
     │
     ▼
classifier.py  ──  mesmo esquema heurística→LLM acima, para o veredito confirmed/not_found/ambiguous
     │
     ▼
orchestrator.py  ──  relatório JSON + CSV em ./runs/ (candidatos, vereditos, telemetria de LLM, métricas de uso híbrido)
     │
     ▼
metrics.py / compute_metrics.py  ──  comparação com ground_truth/ (AVALIAÇÃO — nunca usado pela detecção) ──▶ Precisão / Revocação / F1
```

## Modos experimentais

Três modos, controlados por `AGENT_MODE` no `.env`, `--mode` na CLI, ou pelo menu interativo:

| Modo | LLM é chamado quando... | Uso recomendado |
|---|---|---|
| `heuristic` | **Nunca.** Candidatos/vereditos ambíguos ficam sem confirmação (excluídos/`ambiguous`). | Baseline "só heurística" para comparação/ablação. |
| `hybrid` **(default)** | Só quando a heurística está ambígua. | **O modo do TCC.** Prioriza determinismo; usa o LLM como exceção, não regra. |
| `llm` | **Sempre** — reavalia até candidatos/casos que a heurística já resolveria com confiança. | Experimental. Existe para permitir, no futuro, um estudo de ablação (Heurística vs. Híbrido vs. LLM vs. ZAP) sem reescrever o agente. **Não é o modo recomendado.** |

`--dry-run` nunca chama o LLM, independente do modo pedido (mesmo em `llm`) — é uma trava explícita, não um acidente: testado empiricamente, sem ela `--dry-run --mode llm` fazia uma chamada real ao Gemini (~9s, ~1000 tokens), o que contradiz a promessa de "sem rede real" do modo offline.

**Achado real ao testar o modo `llm` contra o vAPI**: forçar reavaliação de todos os 6 casos de teste + 3 candidatos de inferência gerou até 9 chamadas ao Gemini numa única execução; 4 delas estouraram `LLM_TIMEOUT_S` (30s). O sistema degradou corretamente para o veredito heurístico em cada uma (é exatamente o comportamento de fallback que o design pretende), mas o resultado final teve um caso `ambiguous` que os modos `heuristic`/`hybrid` não têm — evidência real de que "forçar mais LLM" não é estritamente melhor, e uma motivação concreta para o modo `hybrid` ser o recomendado.

## Rastreabilidade de decisão e telemetria de LLM

`agent/llm_telemetry.py` registra **toda** chamada ao Gemini (de `relation_inference.py` e `classifier.py`): módulo de origem, motivo, modelo, duração, tokens de entrada/saída/total (quando a API retorna essa informação — confirmado via introspecção do SDK `google-genai` instalado: `interaction.usage.total_input_tokens` / `total_output_tokens` / `total_tokens` existem de verdade), erro, e se houve fallback para a heurística. Nunca registra a API key nem o prompt/corpo completo — só metadados da chamada.

Cada relatório de execução real (`runs/run_<id>.json`) inclui:

```json
{
  "llm_usage": {
    "summary": {
      "total_calls": 2, "errors": 0, "fallbacks_used": 0,
      "calls_by_module": {"relation_inference": 1, "response_classification": 1},
      "avg_duration_ms": 1850.3,
      "input_tokens_total": 311, "output_tokens_total": 210, "total_tokens_total": 521
    },
    "calls": [ /* um registro completo por chamada */ ]
  },
  "hybrid_usage": {
    "total_test_cases": 6, "heuristic_decisions": 6, "hybrid_decisions": 0, "llm_decisions": 0,
    "avg_heuristic_decision_time_ms": 0.02, "avg_llm_decision_time_ms": null,
    "llm_calls": 0, "llm_errors": 0, "llm_fallbacks": 0
  }
}
```

`compute_metrics.py` imprime esse bloco formatado, além de Precisão/Revocação/F1.

## Requisitos e instalação

- Python 3.10+
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (para o vAPI e, opcionalmente, o baseline ZAP)
- Uma chave de API do [Google AI Studio](https://aistudio.google.com/apikey) — só necessária nos modos `hybrid`/`llm`; o modo `heuristic` funciona sem ela (ver `tests/test_no_api_key.py`)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt          # produção
pip install -r requirements-dev.txt      # + pytest, para rodar a suíte de testes
cp .env.example .env
```

## Subindo o vAPI

O vAPI não faz parte deste repositório — é um projeto externo (Laravel + MySQL) clonado à parte:

```bash
git clone https://github.com/roottusk/vapi.git ../vapi
cd ../vapi
docker compose up -d
```

**A porta real é `8000` no host** (mapeada para a porta 80 do container, onde o `php artisan serve` escuta — confirmado empiricamente, não pela documentação do vAPI, que não menciona isso). Valide:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/vapi/
# esperado: 200
```

`TARGET_BASE_URL` no `.env` já vem configurado para `http://localhost:8000/vapi`.

## Registrando usuários de teste

```bash
python setup_vapi_users.py
```

Registra **4 contas** — A e B, em cada um dos módulos API1 e API5 (tabelas de usuários completamente independentes no vAPI — ver `agent/config.py`) — e imprime um bloco pronto para o `.env`. Não existe endpoint de login no vAPI: o token é `base64(username:senha)`, calculado pelo próprio script.

Este script é o **adapter específico do vAPI** — a única peça do projeto que sabe o formato de registro deste alvo em particular. Ver [Limitações](#limitações-conhecidas) sobre generalização para outros alvos.

## Escolhendo o alvo

O agente **não está travado no vAPI**: qualquer API REST descrita por uma spec OpenAPI 3.x equivalente pode ser testada, escolhendo a spec (`--spec`) e a URL base (`--target-url`) na hora de rodar — via flag ou pelo prompt do menu interativo.

> ⚠️ **Toda execução real (não `--dry-run`) contra qualquer alvo exige autorização explícita.** No menu interativo, a execução pede confirmação antes de qualquer chamada HTTP real — recusar cancela sem nenhuma requisição sair da máquina. No modo via flags/CI, isso vira um aviso não-bloqueante — a responsabilidade é de quem escreve o script.

Trocar de alvo também exige credenciais de teste compatíveis com o modelo de identidade desse alvo — ver [Limitações](#limitações-conhecidas).

## Rodando o agente

### Modo interativo

```bash
python main.py
```

```
=== Agente de Detecção de BOLA ===
1) Rodar em modo dry-run (escolher spec, sem rede real)
2) Rodar execução completa — modo hybrid (recomendado)
3) Rodar execução completa — modo heuristic (LLM nunca chamado)
4) Rodar execução completa — modo llm (experimental; força reavaliação por LLM)
5) Registrar usuários de teste no vAPI (setup_vapi_users.py)
6) Calcular métricas do último relatório (compute_metrics.py)
7) Rodar baseline OWASP ZAP (baseline/run_zap_api_scan.sh)
0) Sair
```

### Modo via flags (scripts/reprodutibilidade)

```bash
python main.py --dry-run                                   # offline, sem chamada de rede nenhuma
python main.py --run                                          # modo hybrid (recomendado), alvo do .env
python main.py --run --mode heuristic                           # baseline "só heurística"
python main.py --run --mode llm                                   # experimental
python main.py --run --spec outra_spec.json --target-url http://host:porta/base
```

Para o vAPI, a spec atual tem 3 operações autenticadas com parâmetro de ID (`GET`/`PUT /api1/user/{api1_id}`, `GET /api5/user/{api5_id}`) → 6 casos de teste cruzados.

## Formato do relatório

`./runs/run_<id>.json` (evidência completa) e `./runs/run_<id>.csv` (resumo tabular, uma linha por caso):

- `experiment_id`, `mode`, `target`, `target_base_url`, `spec_path`, `total_execution_time_ms`.
- `candidates`: cada um com `decision` (`decision_source`/`reason`/`confidence`/`model`).
- `results`: cada caso com `verdict` (`confirmed`/`not_found`/`ambiguous`), `decision`, e as três trocas HTTP completas (`attack_exchange`, `baseline_exchange`, `verification_exchange`) — requisição, resposta, status, latência. O cabeçalho de autenticação vem parcialmente redigido nos logs.
- `llm_usage` / `hybrid_usage`: telemetria e métricas de uso híbrido (ver acima).

## Ground truth e métricas

`ground_truth/vapi.json` documenta as falhas de BOLA confirmadas por **leitura direta do código-fonte** dos controllers Laravel do vAPI:

- **`GET`/`PUT /api1/user/{api1_id}`** — confirmadas, nas duas direções. `API1UsersController` valida usuário/senha mas nunca compara o `id` autenticado com o `{api1_id}` pedido.
- **`GET /api5/user/{api5_id}`** — **não é uma falha de BOLA.** `API5UsersController::show` inclui `->where('id', $id)` na query — verifica corretamente a posse do recurso. A falha real do módulo API5 é `GET /api5/users` (listagem completa, sem parâmetro de ID) — *Broken Function Level Authorization* (API5:2019), fora do escopo deste agente por definição.

O ground truth participa **apenas da avaliação, nunca da detecção** — `agent/relation_inference.py`, `test_generator.py`, `executor.py` e `classifier.py` nunca importam nem leem `ground_truth/`; `tests/test_ground_truth_isolation.py` garante isso automaticamente.

```bash
python compute_metrics.py --run runs/run_<id>.json --ground-truth ground_truth/vapi.json
```

**Resultado em execuções reais contra o vAPI** (modo `hybrid`, 5 execuções + revalidação após esta refatoração): Precisão = Revocação = F1 = **1.000**, desvio padrão = 0 em todas — os 6 vereditos são decididos inteiramente pela heurística determinística; nenhum caso ambíguo acionou o LLM neste ambiente específico. O modo `heuristic` reproduz exatamente o mesmo resultado (esperado, já que não havia nenhum candidato/veredito ambíguo para o LLM desempatar em primeiro lugar).

## Baseline com OWASP ZAP

```bash
./baseline/run_zap_api_scan.sh
```

Sobe o container oficial `zaproxy/zap-stable` e roda `zap-api-scan.py` contra o vAPI real, importando `specs/vapi_openapi.json`, autenticado como **um único usuário** (header estático via `baseline/zap_hooks.py`).

**Resultado real:** 13 tipos de alerta, todos de higiene genérica de segurança (headers ausentes, vazamento de erro 500, `X-Powered-By`) — nenhum relacionado a BOLA/IDOR.

**Conclusão metodologicamente correta** (não "o ZAP é incapaz de detectar BOLA"): *na configuração experimental utilizada — scanner automatizado padrão do ZAP, autenticado com um único usuário, sem o add-on Access Control Testing configurado — não foram identificados os casos de BOLA presentes no conjunto experimental.* As diferenças de contexto fornecido a cada ferramenta são a explicação mais provável, e ficam explícitas aqui como ameaça à validade da comparação:

| | Agente (este projeto) | ZAP (configuração usada) |
|---|---|---|
| Identidades autenticadas | 2 (A e B) | 1 |
| Conhece relação usuário↔objeto | Sim (via `Identity.resource_id`) | Não |
| Testa acesso cruzado entre identidades | Sim (é o mecanismo central) | Não, por padrão |
| Add-on Access Control Testing | N/A | Não configurado |

Um scanner ZAP configurado com o add-on Access Control Testing (2 usuários + regras de acesso por URL) é uma comparação mais forte, ainda não implementada neste repositório — ver [Próximos passos](#próximos-passos).

## Testes automatizados

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

34 testes, mockando toda chamada ao `google.genai.Client` — **nenhum teste faz uma chamada real ao Gemini ou ao vAPI**, e a suíte roda em <1s. Cobre: inferência heurística e seus limiares, fallback para LLM (sucesso/erro/rejeição), classificação heurística (todas as ramificações de status/corpo, incluindo o caso de falso positivo numérico já corrigido), classificação via LLM, os três modos experimentais em ambos os pontos de decisão, métricas (Precisão/Revocação/F1 e uso híbrido), telemetria (registro/reset/truncamento de erro/ausência de secrets), execução sem `GOOGLE_API_KEY` em modo `heuristic`, e não-vazamento de ground truth para o pipeline de detecção.

## Estrutura do repositório

```
agent/
  config.py               configuração (.env), identidades por módulo, modos experimentais
  decision.py              estrutura formal de rastreabilidade de decisão
  llm_telemetry.py          coletor central de chamadas ao LLM
  openapi_parser.py         parser de OpenAPI 3.x
  relation_inference.py     heurística + LLM: acha candidatos a BOLA
  test_generator.py         gera os casos de teste cruzados A↔B
  http_client.py            cliente HTTP com log estruturado de evidência
  executor.py                executa os casos contra o alvo real
  classifier.py              decide o veredito (heurística + LLM)
  orchestrator.py             junta tudo, grava ./runs/ (JSON + CSV)
  metrics.py                  Precisão/Revocação/F1 + métricas de uso híbrido
tests/                          suíte pytest (LLM mockado)
specs/vapi_openapi.json          spec OpenAPI do vAPI (reconstruída e corrigida manualmente)
ground_truth/vapi.json            gabarito validado por leitura de código-fonte
baseline/                          script + hook do baseline OWASP ZAP
main.py · setup_vapi_users.py · compute_metrics.py
requirements.txt · requirements-dev.txt
```

## Sobre a especificação OpenAPI

A spec OpenAPI é tratada aqui como **representação estruturada dos endpoints documentados da API** — não como garantia de que descreve toda a superfície real da aplicação. A capacidade de descoberta do agente é diretamente limitada pela qualidade e completude da spec: um endpoint não documentado, ou um parâmetro de identificador com nome pouco convencional, simplesmente não vira candidato. A spec usada neste projeto (`specs/vapi_openapi.json`) foi reconstruída manualmente a partir da coleção Postman pública do vAPI e corrigida por leitura do código-fonte dos controllers — não é a spec "oficial" do projeto vAPI (que, aliás, não publica uma).

## Limitações conhecidas

Documentadas de propósito — o objetivo é deixar a metodologia cientificamente defensável, não escondida atrás de resultados favoráveis.

- **Número reduzido de casos experimentais**: 6 casos de teste, 2 falhas de BOLA confirmadas, um único ambiente (vAPI). F1=1.000 aqui é validação de que o mecanismo funciona corretamente ponta a ponta, não evidência estatística forte generalizável.
- **Avaliação concentrada no vAPI**: nenhum segundo ambiente vulnerável foi testado até agora.
- **Dependência da qualidade do OpenAPI**: ver seção acima.
- **Componentes ainda específicos do vAPI**: `setup_vapi_users.py` inteiro, e a convenção de identidade por módulo em `Config.identity()` (assume que cada "módulo" — primeiro segmento do path — tem sua própria base de usuários; um alvo com uma única base de usuários compartilhada entre todos os endpoints exigiria uma simplificação equivalente, ainda não implementada). O restante do pipeline (`openapi_parser`, `relation_inference`, `test_generator`, `http_client`, `executor`, `classifier`) é genérico.
- **LLM acionado só em ambiguidade (modo `hybrid`)**: no conjunto atual, isso significa que o LLM nunca é chamado de fato — os 6 casos são todos claros o suficiente para a heurística. Isso não é um defeito do design híbrido; é uma limitação do conjunto experimental atual, que ainda não inclui um caso genuinamente ambíguo. O modo `llm` existe para pelo menos observar o comportamento do modelo nesse cenário, mas força artificialmente a situação em vez de refletir um caso real.
- **Modo `llm` sob volume real esbarra em timeout**: 4 de 9 chamadas forçadas expiraram em 30s numa execução real (ver "Modos experimentais" acima) — não invalida o design (o fallback funcionou), mas mostra que esse modo não escala trivialmente sem ajuste de timeout/paralelismo/retry.
- **Duas identidades autenticadas, path único de descoberta de objeto**: sem endpoint de listagem no vAPI, o "objeto conhecido" de cada identidade é sempre o próprio perfil — não generaliza para recursos subordinados (ex.: pedidos de um usuário) sem uma fonte adicional de identificadores.
- **Endpoints com múltiplos parâmetros de identificador**: o gerador de casos substitui todos pelo ID da vítima — correto para os endpoints do vAPI avaliados (um parâmetro cada), incorreto para algo como `/users/{user_id}/orders/{order_id}`.
- **Autorização baseada em contexto externo** (ex.: uma regra de negócio que depende de estado fora da própria API) não é modelada — o agente só enxerga o que a API expõe via HTTP.
- **Limitações do baseline ZAP**: configuração de um único usuário, sem Access Control Testing — ver seção do ZAP acima e "Ameaças à validade".

## Ameaças à validade

- A comparação com o ZAP usa uma configuração deliberadamente mínima (ver tabela na seção do ZAP) — não representa o teto de capacidade do ZAP quando configurado por um analista com o mesmo conhecimento de domínio que o agente recebe via OpenAPI.
- O ground truth foi construído por um único revisor (leitura do código-fonte), sem segunda validação independente.
- Todas as execuções até agora rodaram num único ambiente de laboratório (vAPI), num único momento — não há dados sobre estabilidade ao longo do tempo ou sob carga de rede diferente.
- O modo `hybrid` nunca foi exercitado com um caso genuinamente ambíguo real (ver Limitações) — sua vantagem sobre `heuristic` permanece teórica até que o conjunto experimental inclua um caso assim.

## Próximos passos

Em ordem de prioridade recomendada:

1. **Adicionar um segundo ambiente vulnerável** (ex.: crAPI, DVGA) — generaliza a avaliação além de um único alvo.
2. **Criar casos genuinamente ambíguos** para exercitar o modo `hybrid` de verdade (hoje ele nunca precisa decidir nada, porque o vAPI só tem casos claros).
3. **Estudo de ablação formal**: Heurística vs. Híbrido vs. LLM vs. ZAP, usando a exportação CSV/JSON com `experiment_id`/`mode` já preparada para isso.
4. **Ampliar o ground truth** (mais endpoints, mais de um ambiente, segunda validação independente).
5. **Melhorar a generalização**: extrair uma interface formal de "adapter" (hoje `setup_vapi_users.py` e `Config.identity()` são vAPI-específicos por convenção, não por contrato).
6. **Tornar a autenticação totalmente configurável** por spec (hoje o esquema de header customizado é assumido; um alvo com OAuth/JWT padrão exigiria ajuste manual em `http_client.py`).
7. **Baseline ZAP com Access Control Testing** configurado (2 usuários + regras de acesso), como segunda linha de base mais forte para a comparação.
