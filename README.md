# harness-authority — a trava que o vigiado não desliga

Este repositório existe por causa de uma frase que era **parcialmente falsa** no
[`danzeroum/project`](https://github.com/danzeroum/project):

> Uma trava que o vigiado pode desligar em silêncio não é uma trava.

O molde tem uma camada local de verificação (`ci/verify_protection.py`) que confere se as proteções
de branch e de tag estão ligadas. Ela é necessária e **não basta**: mora no mesmo repositório que
fiscaliza. Um PR com privilégio suficiente remove o passo e a asserção que o vigia **no mesmo
commit**, e o CI fica verde porque a trava saiu junto com quem reclamaria dela.

É circular por construção, e nenhuma quantidade de código lá dentro resolve. Aqui não é circular:
uma mudança no molde não alcança este arquivo.

## O que ele faz

Todo dia, sozinho, olha o `danzeroum/project` **de fora** e pergunta uma coisa só:

> As travas que se exige dele estão de fato ligadas **agora**?

O que se exige está em `EXIGIDAS_PADRAO`, versionado, e seu digest entra no atestado — é o que
permite dizer *"foi ESTA regra que passou"* em vez de *"passou alguma regra num momento qualquer"*.

| Eixo | Exigência |
|---|---|
| tags `refs/tags/v*` | ruleset ativo com `deletion` + `non_fast_forward` + `update`, bypass vazio |
| tags — **proibido** | `creation`, que trancaria o `workflow_dispatch` de release do molde |
| branch `main` | review obrigatório **de code owner**, force push recusado |

`creation` ser **lacuna** e não virtude é o detalhe que separa uma trava útil de uma trava que
alguém desliga inteira para conseguir trabalhar. Exigir demais e exigir de menos falham no mesmo
lugar.

## Três decisões que valem mais que o código

**Núcleo puro.** `verificar(rulesets, protection, exigidas) -> lacunas` não abre socket. Quem tem a
rede é o CLI. Não é estilo: um verificador que faz I/O confunde *"a trava está desligada"* com
*"não consegui olhar"*, e as duas conclusões pedem reações opostas. Ele **recusa** ser chamado com
`None` — devolver "sem lacunas" a partir de ausência de resposta é como um verde falso nasce.

**Silêncio nunca carimba.** Sem credencial, com 403 na leitura dos rulesets ou com a API fora do
ar: **nenhum atestado é emitido** e o job sai indeterminado.

**Atestado só de estado limpo.** Havendo lacuna, sai **laudo** e não sai atestado. Um atestado com
ressalva seria um *"sim, mas"* que o consumidor lê como sim. O laudo é onde a lacuna vive, com
data — e é ele que fecha `RISK-EXT-001` no dia em que os rulesets forem ligados.

## Validade de 25h, e o excedente é a decisão

O cron é diário; o atestado vale 25 horas. Uma execução perdida faz o atestado anterior **expirar**
em vez de continuar valendo — e expirado bloqueia no molde do mesmo modo que ausente. É o que faz
"o verificador parou de rodar" se resolver sozinho, sem depender de alguém perceber.

## Como o molde consome

O atestado chega ao `danzeroum/project` por **PR** — nunca push direto. O ruleset da `main` de lá
recusa push direto para todos, e um verificador que pudesse escrever lá seria capaz de reescrever a
evidência das auditorias anteriores. A autoridade **propõe**; quem integra é o portão normal.

Com `harness.yaml:external_audit.enabled: true`, o molde exige o atestado: ausente, ilegível, fora
do schema ou expirado **bloqueia**.

## O que falta para isto virar autoridade de fato

Duas coisas, e as duas são de admin — nenhuma é código:

1. **Ligar os rulesets** no `danzeroum/project` (hoje as tags não têm nenhum; é a lacuna que o
   laudo registra).
2. **Tornar obrigatório**, em ruleset da `main` com bypass vazio, o check desta autoridade.
   **Sem este passo, o atestado é registro e não trava** — quem pode mergear no molde escreveria
   qualquer JSON no lugar dele.

## Uma lacuna conhecida, declarada em vez de escondida

`check_external_attestation`, no molde, valida existência, legibilidade, schema e validade. O campo
`issuer` é **exigido pelo schema e nunca comparado com nada** — hoje, um atestado emitido por
qualquer identidade passa.

Isso está em `tests/test_verificador.py::test_EMISSOR_NAO_AUTORIZADO_AINDA_PASSA_e_isto_esta_documentado`,
que afirma o comportamento **atual** de propósito. Ele vira vermelho no dia em que a emenda
`authorized_issuer` entrar no molde — e ficar vermelho será a confirmação de que a lacuna fechou.
Um teste que descreve o buraco é mais honesto que um `skip` que o esconde.

## Rodar localmente

```bash
pip install -r requirements.txt
MOLDE_ROOT=/caminho/para/project python -m pytest tests -q
```

Os testes de sistema copiam o molde, ligam `external_audit` e conferem que o consumo muda de cor —
verde com atestado válido, bloqueio com expirado, bloqueio com ausente. É o nível que importa: um
verificador correto cujo atestado o consumidor ignora é autoridade de papel.
