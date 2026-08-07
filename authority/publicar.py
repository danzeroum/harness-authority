#!/usr/bin/env python3
"""Entrega o atestado ao molde por PR — a única escrita que este repositório faz no alvo.

Por que PR e não push direto: o ruleset da `main` do molde recusa push direto para todos, e um
verificador que pudesse escrever lá seria capaz de reescrever a evidência das auditorias
anteriores. A autoridade PROPÕE; quem integra continua sendo o portão normal do molde.

Por que uma branch de nome FIXO por dia: o cron roda diariamente, e uma branch nova a cada
execução produziria uma fila de PRs abertos que ninguém fecha — ruído que ensina a ignorar. A
branch é reescrita, e a reescrita é legítima porque o conteúdo dela é derivado, não histórico.

Uso: python authority/publicar.py --repo danzeroum/project --atestado a.json --caminho harness/...
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://api.github.com"
BRANCH = "autoridade/atestado-de-protecao"

# Propor não é entregar, e a distância entre as duas custou 19h de bloqueio. O ciclo de 06/08 abriu
# o PR #55 com todos os checks verdes e voltou exit 0 — "atestado proposto" — enquanto o merge
# nunca acontecia. O passo saiu VERDE afirmando ter renovado algo que não renovou.
#
# Daqui em diante a publicação só é sucesso se a proposta estiver INTEGRÁVEL. Não é o mesmo que
# "mergeada": quem mergeia é o portão do molde, e é assim que deve ser. É "não há nada do lado da
# autoridade impedindo o merge".
EXIT_INDETERMINADO = 3

PRONTO = "pronto"
RESSINCRONIZAR = "ressincronizar"
INDETERMINADO = "indeterminado"

# Quanto esperar o GitHub CALCULAR a mergeabilidade. `mergeable_state` chega `unknown` logo após
# abrir ou atualizar um PR, e some sozinho em segundos. Isto é espera por um cálculo assíncrono,
# não re-tentativa de re-sincronização — a diferença importa, porque a segunda é proibida em laço
# e esta é limitada e termina em indeterminação, nunca em nova ação.
ESPERA_CALCULO_S = 3
TENTATIVAS_CALCULO = 8


# --------------------------------------------------------------------------------------
# Núcleo puro
# --------------------------------------------------------------------------------------

def decidir_acao(*, estado: str, ja_ressincronizou: bool) -> tuple[str, str]:
    """O que fazer com a proposta aberta, a partir do `mergeable_state` que a API devolveu.

    Função PURA, e pela mesma razão do ci/verify_approval.py do molde: sem esta separação,
    "a API não respondeu" e "a proposta está travada" produziriam o mesmo vermelho, e a leitura
    barata venceria por hábito. Aqui cada estado tem nome, e o teste alcança todos sem rede.
    """
    # `blocked` é o estado NORMAL da proposta recém-aberta: faltam os checks obrigatórios passarem.
    # Não é problema da autoridade — é o portão do molde fazendo o trabalho dele. `unstable` é o
    # mesmo caso com algum check não obrigatório em curso.
    if estado in ("clean", "blocked", "unstable", "has_hooks"):
        return PRONTO, f"proposta integrável (mergeable_state={estado})"

    # A CORRIDA QUE ESTA CP FECHA. O commit foi montado sobre a `main` que existia há segundos;
    # se outro merge entrou no meio, a proposta nasce atrasada. O auto-merge nativo NÃO atualiza
    # branch atrasada — ele espera, e esperar aqui significa esperar até o atestado vencer.
    if estado == "behind":
        if ja_ressincronizou:
            # UMA vez, e o limite é a decisão. Um laço de re-sincronização contra uma `main` que
            # recebe merges continuamente é uma corrida que a autoridade perde para sempre, gastando
            # cota de API e produzindo verde a cada volta. O timer obsoleto do PR #39 é o precedente.
            return INDETERMINADO, ("ainda atrasada depois de uma re-sincronização — a `main` se move "
                                   "mais rápido do que a proposta acompanha; desistindo com alarme "
                                   "em vez de entrar em laço")
        return RESSINCRONIZAR, "proposta atrasada em relação à base — re-sincronizando uma vez"

    # Conflito REAL, que é outra coisa: o atestado que a autoridade escreve colidiu com alguém que
    # mexeu no mesmo arquivo. Re-sincronizar não resolve, e forçar seria a autoridade sobrescrevendo
    # evidência alheia — exatamente o poder que este repositório não tem por desenho.
    if estado == "dirty":
        return INDETERMINADO, ("conflito real na proposta, não apenas atraso — a autoridade PROPÕE, "
                               "não resolve conflito no molde")

    if estado == "draft":
        return INDETERMINADO, "proposta em rascunho — não integrável, e a autoridade não a promove"

    # `unknown` que sobreviveu à espera, ou um estado que a API passou a devolver e este código não
    # conhece. Indeterminado é a resposta honesta: o fiscal conseguiu perguntar e não entendeu a
    # resposta, o que não é a mesma coisa que "está tudo bem".
    return INDETERMINADO, f"mergeabilidade não determinada (mergeable_state={estado!r})"


def capacidade_de_automerge(repo_info: dict) -> str | None:
    """Devolve o motivo quando o alvo NÃO consegue auto-mergear; None quando consegue.

    Esta é a trava sobre a caixa. A renovação diária depende de `Allow auto-merge` estar marcado em
    Settings — uma configuração que não aparece em nenhum arquivo, que nenhum teste alcança, e cuja
    ausência a CP-037 (corretamente, no escopo dela) reporta como `::warning::`. Um aviso diário que
    não muda nada é um aviso que se aprende a pular: foi assim que o #55 ficou 19h parado com o job
    verde. Aqui a ausência da capacidade tem nome e sai indeterminada.
    """
    if repo_info.get("allow_auto_merge") is True:
        return None
    return ("`Allow auto-merge` está DESMARCADO no alvo — sem essa capacidade a proposta diária "
            "fica aguardando merge humano e o atestado vence em 25h. Ação de admin, uma caixa: "
            "Settings → General → Pull Requests → marcar 'Allow auto-merge'.")


def _api(url: str, token: str, metodo: str = "GET", corpo: dict | None = None) -> dict | None:
    dados = json.dumps(corpo).encode("utf-8") if corpo is not None else None
    req = urllib.request.Request(url, data=dados, method=metodo, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "harness-authority",
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 - URL montada aqui
            corpo_bruto = r.read().decode("utf-8")
            return json.loads(corpo_bruto) if corpo_bruto else {}
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 422):
            return None
        raise


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Entrega o atestado ao molde por PR.")
    p.add_argument("--repo", required=True)
    p.add_argument("--atestado", required=True)
    p.add_argument("--caminho", default="harness/state/protection-attestation.json")
    p.add_argument("--base", default="main")
    args = p.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("• indeterminado: sem credencial para entregar o atestado.", file=sys.stderr)
        return 3

    conteudo = open(args.atestado, "rb").read()
    import base64
    b64 = base64.b64encode(conteudo).decode("ascii")

    base = _api(f"{API}/repos/{args.repo}/git/ref/heads/{args.base}", token)
    if base is None:
        print(f"• indeterminado: não consegui resolver {args.base} em {args.repo}.", file=sys.stderr)
        return 3
    sha_base = base["object"]["sha"]

    # O COMMIT É MONTADO ANTES DE A REF SE MEXER, e essa ordem é a correção de um defeito real.
    #
    # A primeira versão fazia dois passos: realinhava a branch na base (PATCH force) e só depois
    # escrevia o arquivo. No instante entre um e outro, a branch ficava IDÊNTICA à base — e o
    # GitHub fecha automaticamente um PR cuja head não difere mais da base. O PR #47 morreu assim,
    # e a execução seguinte abriu o #49 sem que ninguém entendesse por quê. Um estado intermediário
    # que só existe por microssegundos ainda é um estado, e alguém observa.
    #
    # Aqui a ref só muda uma vez, e nunca para um valor igual à base: o blob, a árvore e o commit
    # são criados primeiro, com a base como pai.
    blob = _api(f"{API}/repos/{args.repo}/git/blobs", token, "POST",
                {"content": b64, "encoding": "base64"})
    if blob is None:
        print("• indeterminado: o blob do atestado não pôde ser criado.", file=sys.stderr)
        return 3

    arvore = _api(f"{API}/repos/{args.repo}/git/trees", token, "POST",
                  {"base_tree": sha_base,
                   "tree": [{"path": args.caminho, "mode": "100644", "type": "blob",
                             "sha": blob["sha"]}]})
    if arvore is None:
        print("• indeterminado: a árvore não pôde ser criada.", file=sys.stderr)
        return 3

    commit = _api(f"{API}/repos/{args.repo}/git/commits", token, "POST",
                  {"message": "autoridade: atestado de proteção de refs",
                   "tree": arvore["sha"], "parents": [sha_base]})
    if commit is None:
        print("• indeterminado: o commit não pôde ser criado.", file=sys.stderr)
        return 3

    if commit["tree"]["sha"] == _api(f"{API}/repos/{args.repo}/git/commits/{sha_base}",
                                     token)["tree"]["sha"]:
        print("✓ atestado idêntico ao que já está na base — nada a propor.")
        return 0

    ref = _api(f"{API}/repos/{args.repo}/git/refs", token, "POST",
               {"ref": f"refs/heads/{BRANCH}", "sha": commit["sha"]})
    if ref is None:
        _api(f"{API}/repos/{args.repo}/git/refs/heads/{BRANCH}", token, "PATCH",
             {"sha": commit["sha"], "force": True})

    abertos = _api(f"{API}/repos/{args.repo}/pulls?head={args.repo.split('/')[0]}:{BRANCH}"
                   f"&state=open", token) or []
    if abertos:
        numero = abertos[0]["number"]
        print(f"✓ atestado atualizado no PR #{numero}.")
    else:
        pr = _api(f"{API}/repos/{args.repo}/pulls", token, "POST", {
            "title": "autoridade: atestado de proteção de refs",
            "head": BRANCH, "base": args.base,
            "body": "Emitido por `danzeroum/harness-authority`, que audita este repositório de fora."
                    "\n\nO atestado tem validade de 25h: uma execução perdida do cron o faz expirar "
                    "em vez de continuar valendo. Expirado bloqueia do mesmo modo que ausente.\n",
        })
        if pr is None:
            print("• indeterminado: o PR não pôde ser aberto.", file=sys.stderr)
            return EXIT_INDETERMINADO
        numero = pr["number"]
        print(f"✓ atestado proposto no PR #{numero}.")

    return _confirmar_entrega(repo=args.repo, token=token, numero=numero)


def _estado_do_pr(repo: str, token: str, numero: int) -> str:
    """`mergeable_state`, esperando o cálculo assíncrono do GitHub sair de `unknown`."""
    estado = "unknown"
    for _ in range(TENTATIVAS_CALCULO):
        pr = _api(f"{API}/repos/{repo}/pulls/{numero}", token)
        if pr is None:
            return "unknown"
        estado = pr.get("mergeable_state") or "unknown"
        if estado != "unknown":
            return estado
        time.sleep(ESPERA_CALCULO_S)
    return estado


def _confirmar_entrega(*, repo: str, token: str, numero: int) -> int:
    """A proposta está integrável? Sucesso aqui é a promessa que o exit 0 passa a valer."""
    info = _api(f"{API}/repos/{repo}", token) or {}
    falta = capacidade_de_automerge(info)

    estado = _estado_do_pr(repo, token, numero)
    acao, motivo = decidir_acao(estado=estado, ja_ressincronizou=False)

    if acao == RESSINCRONIZAR:
        print(f"• {motivo}")
        # A MESMA operação que um humano faria no botão "Update branch". Não é merge, não atropela
        # ruleset nenhum: cria um merge da base na cabeça da proposta.
        _api(f"{API}/repos/{repo}/pulls/{numero}/update-branch", token, "PUT", {})
        estado = _estado_do_pr(repo, token, numero)
        acao, motivo = decidir_acao(estado=estado, ja_ressincronizou=True)

    if acao != PRONTO:
        print(f"::error::renovação do atestado NÃO confirmada no PR #{numero}: {motivo}",
              file=sys.stderr)
        if falta:
            print(f"::error::{falta}", file=sys.stderr)
        print("• indeterminado: o atestado anterior expira em ≤25h e o molde bloqueia sozinho — "
              "que é o comportamento correto para uma renovação que não fechou.", file=sys.stderr)
        return EXIT_INDETERMINADO

    if falta:
        # A proposta está integrável e mesmo assim a entrega não fecha sozinha: falta a capacidade
        # no alvo. Verde aqui seria "achei que renovei".
        print(f"::error::{falta}", file=sys.stderr)
        return EXIT_INDETERMINADO

    print(f"✓ proposta integrável no PR #{numero}: {motivo}. O portão do molde a mergeia.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
