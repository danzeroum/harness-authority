#!/usr/bin/env python3
"""Cria o GitHub App a partir de um MANIFESTO declarado, e grava os secrets.

Por que existe, e não é conveniência: o passo manual pedia marcar três permissões numa página
com dezenas de campos. Permissão marcada a mais não avisa ninguém — a autoridade externa passaria
a poder escrever onde não devia, e o único registro disso seria a memória de quem clicou.

Com o manifesto, as permissões viram `authority/app-manifest.json`: versionado, revisável em
diff, e idêntico a cada recriação. A página de criação vem preenchida a partir dele. O que sobra
de manual é o que TEM de ser manual — você confirmar que quer criar, e escolher onde instalar.

O fluxo (GitHub App Manifest flow):

  1. este script sobe um servidor local só para receber a volta;
  2. abre a página do GitHub já preenchida com o manifesto;
  3. você confirma; o GitHub redireciona de volta com um `code` de uso único;
  4. o script troca o `code` por app_id + slug + chave privada;
  5. grava APP_ID e PRIVATE_KEY como secrets, SEM passar a chave por disco.

Uso:  python authority/criar_app.py [--repo-secrets danzeroum/harness-authority] [--porta 8765]
"""

from __future__ import annotations

import argparse
import http.server
import json
import secrets as _secrets
import subprocess
import sys
import threading
import urllib.request
import webbrowser
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
MANIFESTO = RAIZ / "app-manifest.json"

_PAGINA = """<!doctype html><meta charset="utf-8"><title>criar o App</title>
<body style="font-family:system-ui;max-width:40rem;margin:4rem auto;line-height:1.6">
<h2>Criando o GitHub App a partir do manifesto</h2>
<p>Se a página do GitHub não abrir sozinha, clique no botão.</p>
<form id="f" method="post" action="https://github.com/settings/apps/new?state={state}">
  <input type="hidden" name="manifest" id="m">
  <button type="submit" style="font-size:1rem;padding:.6rem 1rem">Abrir o GitHub</button>
</form>
<script>
  document.getElementById("m").value = {manifesto};
  document.getElementById("f").submit();
</script>
</body>"""

_FIM = """<!doctype html><meta charset="utf-8"><body style="font-family:system-ui;margin:4rem">
<h2>{titulo}</h2><p>{corpo}</p><p>Pode fechar esta aba e voltar ao terminal.</p></body>"""


def montar_pagina(manifesto: dict, state: str) -> str:
    """O HTML que faz o POST. O manifesto entra como JSON dentro de JSON — daí o duplo dump."""
    return _PAGINA.format(state=state, manifesto=json.dumps(json.dumps(manifesto)))


def converter(code: str) -> dict:
    """Troca o code pelo App. O endpoint é NÃO autenticado: o `code` é a credencial, de uso único
    e vida curta — por isso ele nunca é impresso nem gravado."""
    req = urllib.request.Request(
        f"https://api.github.com/app-manifests/{code}/conversions",
        method="POST",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "harness-authority"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 - URL montada aqui
        return json.loads(r.read().decode("utf-8"))


def gravar_secret(repo: str, nome: str, valor: str) -> None:
    """Via stdin do `gh`, para que a chave privada NÃO toque o disco em momento nenhum.

    Um .pem em ~/Downloads é uma chave de vida longa num diretório que ninguém limpa.
    """
    r = subprocess.run(["gh", "secret", "set", nome, "--repo", repo],
                       input=valor, text=True, capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"✗ falhou ao gravar o secret {nome}: {r.stderr.strip()}")
    print(f"✓ secret {nome} gravado em {repo}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Cria o App a partir do manifesto declarado.")
    p.add_argument("--repo-secrets", default="danzeroum/harness-authority")
    p.add_argument("--porta", type=int, default=8765)
    p.add_argument("--salvar-pem", metavar="CAMINHO",
                   help="também grava a chave em arquivo (por padrão ela não toca o disco)")
    args = p.parse_args(argv)

    manifesto = json.loads(MANIFESTO.read_text(encoding="utf-8"))
    manifesto["redirect_url"] = f"http://127.0.0.1:{args.porta}/callback"
    state = _secrets.token_urlsafe(24)
    recebido: dict = {}
    pronto = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # silêncio: o log do servidorzinho não interessa a ninguém
            pass

        def do_GET(self):  # noqa: N802 - assinatura da stdlib
            from urllib.parse import parse_qs, urlparse
            url = urlparse(self.path)
            if url.path == "/":
                corpo = montar_pagina(manifesto, state)
            elif url.path == "/callback":
                q = parse_qs(url.query)
                # O `state` é conferido: sem isso, qualquer página aberta no seu navegador poderia
                # entregar um `code` de OUTRO App a este script, e você gravaria como secret a
                # credencial de algo que não criou.
                if q.get("state", [None])[0] != state:
                    corpo = _FIM.format(titulo="Recusado",
                                        corpo="o <code>state</code> não confere — a volta não veio "
                                              "do pedido que este script fez.")
                elif "code" not in q:
                    corpo = _FIM.format(titulo="Sem code", corpo="o GitHub não devolveu um code.")
                else:
                    recebido["code"] = q["code"][0]
                    corpo = _FIM.format(titulo="Recebido",
                                        corpo="o script está trocando o code pela chave.")
            else:
                self.send_response(404)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(corpo.encode("utf-8"))
            if "code" in recebido:
                pronto.set()

    servidor = http.server.HTTPServer(("127.0.0.1", args.porta), Handler)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()

    inicio = f"http://127.0.0.1:{args.porta}/"
    print(f"1. abrindo {inicio}")
    print("2. confirme a criação no GitHub (nome e permissões já vêm do manifesto)")
    webbrowser.open(inicio)

    if not pronto.wait(timeout=600):
        print("✗ nada voltou em 10 minutos — nenhum App foi criado por este script.",
              file=sys.stderr)
        return 3
    servidor.shutdown()

    app = converter(recebido["code"])
    print(f"\n✓ App criado: {app['slug']} (id {app['id']})")
    print(f"  instalar em: {app['html_url']}/installations/new")

    gravar_secret(args.repo_secrets, "APP_ID", str(app["id"]))
    gravar_secret(args.repo_secrets, "PRIVATE_KEY", app["pem"])

    if args.salvar_pem:
        destino = Path(args.salvar_pem)
        destino.write_text(app["pem"], encoding="utf-8")
        destino.chmod(0o600)
        print(f"• chave também gravada em {destino} — apague quando não precisar mais.")

    print("\nFalta um passo, e ele é manual de propósito: INSTALAR o App em danzeroum/project.")
    print("Instalar é conceder acesso, e conceder acesso é decisão de quem pode concedê-la.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
