#!/usr/bin/env python3
"""Cunha o token de instalação do GitHub App — em código nosso, e isso é deliberado.

A alternativa seria uma action de terceiro no workflow. Num repositório cuja única função é ser
confiável, importar a cunhagem da credencial de uma dependência que se resolve por tag móvel seria
contradizer o produto: a autoridade externa passaria a depender de código que ninguém aqui leu e
que pode mudar sob o mesmo nome. Quarenta linhas nossas são auditáveis; `@v1` não é.

A identidade do emissor é LIDA da API (`GET /app` → `slug`), nunca digitada. Um `issuer.identity`
escrito à mão no workflow seria o próprio emissor afirmando quem é.

Uso (como biblioteca):  token, slug = cunhar(app_id, private_key_pem, "danzeroum/project")
"""

from __future__ import annotations

import json
import time
import urllib.request

API = "https://api.github.com"


def _get(url: str, token: str, metodo: str = "GET") -> dict:
    req = urllib.request.Request(url, method=metodo, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "harness-authority",
    })
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 - URL montada aqui
        return json.loads(r.read().decode("utf-8"))


def montar_claims(app_id: str, agora: int | None = None) -> dict:
    """Os claims do JWT. Função pura, para que a janela seja testável sem chave.

    `iat` recuado em 60s absorve relógio dessincronizado entre runner e GitHub — sem isso, um
    atraso de segundos produz 401, e 401 aqui vira 'indeterminado' num dia em que nada estava
    errado. Expiração curta (9 min) porque o JWT só serve para trocar por token de instalação.
    """
    t = agora if agora is not None else int(time.time())
    return {"iat": t - 60, "exp": t + 540, "iss": str(app_id)}


def cunhar(app_id: str, private_key_pem: str, repository: str) -> tuple[str, str]:
    """Devolve (token_de_instalacao, slug_do_app). Levanta se a credencial não alcançar o alvo."""
    import jwt  # PyJWT

    assinado = jwt.encode(montar_claims(app_id), private_key_pem, algorithm="RS256")
    slug = _get(f"{API}/app", assinado).get("slug") or f"app-{app_id}"

    dono, nome = repository.split("/", 1)
    instalacao = _get(f"{API}/repos/{dono}/{nome}/installation", assinado)
    concessao = _get(f"{API}/app/installations/{instalacao['id']}/access_tokens", assinado, "POST")
    return concessao["token"], slug
