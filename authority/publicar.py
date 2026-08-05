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
import urllib.error
import urllib.request

API = "https://api.github.com"
BRANCH = "autoridade/atestado-de-protecao"


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

    # Cria a branch, ou a realinha na base atual. Realinhar é o que impede o PR de acumular um
    # diff de conteúdo antigo quando a main andou entre duas execuções do cron.
    ref = _api(f"{API}/repos/{args.repo}/git/refs", token, "POST",
               {"ref": f"refs/heads/{BRANCH}", "sha": sha_base})
    if ref is None:
        _api(f"{API}/repos/{args.repo}/git/refs/heads/{BRANCH}", token, "PATCH",
             {"sha": sha_base, "force": True})

    atual = _api(f"{API}/repos/{args.repo}/contents/{args.caminho}?ref={BRANCH}", token)
    corpo = {"message": "autoridade: atestado de proteção de refs",
             "content": b64, "branch": BRANCH}
    if atual and atual.get("sha"):
        if atual.get("content", "").replace("\n", "") == b64:
            print("✓ atestado idêntico ao que já está na branch — nada a propor.")
            return 0
        corpo["sha"] = atual["sha"]
    _api(f"{API}/repos/{args.repo}/contents/{args.caminho}", token, "PUT", corpo)

    abertos = _api(f"{API}/repos/{args.repo}/pulls?head={args.repo.split('/')[0]}:{BRANCH}"
                   f"&state=open", token) or []
    if abertos:
        print(f"✓ atestado atualizado no PR #{abertos[0]['number']}.")
        return 0

    pr = _api(f"{API}/repos/{args.repo}/pulls", token, "POST", {
        "title": "autoridade: atestado de proteção de refs",
        "head": BRANCH, "base": args.base,
        "body": "Emitido por `danzeroum/harness-authority`, que audita este repositório de fora.\n\n"
                "O atestado tem validade de 25h: uma execução perdida do cron o faz expirar em vez "
                "de continuar valendo. Expirado bloqueia do mesmo modo que ausente.\n",
    })
    if pr is None:
        print("• indeterminado: o PR não pôde ser aberto.", file=sys.stderr)
        return 3
    print(f"✓ atestado proposto no PR #{pr['number']}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
