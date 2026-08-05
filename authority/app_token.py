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


class NaoAlcanca(Exception):
    """A credencial não chega ao alvo — e a mensagem diz QUAL das três razões.

    Existe porque a primeira execução real falhou com um traceback de `HTTPError: 404` e nada mais.
    Um 404 aqui tem três causas distintas, com três consertos distintos, e o rastro de pilha não
    distingue nenhuma: chave errada, App não instalado, instalação sem acesso ao repositório.
    Erro que não diz o que fazer transfere ao leitor o trabalho de descobrir.
    """


def cunhar(app_id: str, private_key_pem: str, repository: str) -> tuple[str, str]:
    """Devolve (token_de_instalacao, slug_do_app). Levanta NaoAlcanca com o motivo."""
    import urllib.error

    import jwt  # PyJWT

    assinado = jwt.encode(montar_claims(app_id), private_key_pem, algorithm="RS256")

    try:
        slug = _get(f"{API}/app", assinado).get("slug") or f"app-{app_id}"
    except urllib.error.HTTPError as exc:
        raise NaoAlcanca(
            f"o GitHub não reconheceu a identidade do App (HTTP {exc.code}). APP_ID e PRIVATE_KEY "
            f"precisam ser do MESMO App, e a chave precisa estar inteira — um .pem colado sem a "
            f"linha final costuma produzir exatamente isto.") from exc

    dono, nome = repository.split("/", 1)
    try:
        instalacao = _get(f"{API}/repos/{dono}/{nome}/installation", assinado)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            # O 404 aqui tem DUAS causas, e a primeira versão desta mensagem afirmava só a
            # primeira — com confiança que a evidência não sustentava. Perguntar quantas
            # instalações o App tem distingue as duas, e a diferença muda onde a pessoa clica.
            try:
                instalacoes = _get(f"{API}/app/installations", assinado)
            except urllib.error.HTTPError:
                instalacoes = []
            if instalacoes:
                onde = ", ".join(str((i.get("account") or {}).get("login")) for i in instalacoes)
                raise NaoAlcanca(
                    f"o App '{slug}' ESTÁ instalado ({len(instalacoes)} instalação(ões) em "
                    f"{onde}), mas nenhuma delas alcança {repository} — instalar na conta e dar "
                    f"acesso ao repositório são passos separados. Abra "
                    f"https://github.com/settings/installations, clique em Configure no "
                    f"'{slug}' e marque {repository} em 'Repository access'.") from exc
            raise NaoAlcanca(
                f"o App '{slug}' não está instalado em lugar nenhum. Instalar é conceder acesso, e "
                f"é o único passo que não se automatiza: "
                f"https://github.com/settings/apps/{slug}/installations — instale na sua conta e "
                f"marque {repository}.") from exc
        raise NaoAlcanca(f"não foi possível resolver a instalação em {repository} "
                         f"(HTTP {exc.code}).") from exc

    try:
        concessao = _get(f"{API}/app/installations/{instalacao['id']}/access_tokens",
                         assinado, "POST")
    except urllib.error.HTTPError as exc:
        raise NaoAlcanca(
            f"a instalação existe mas não emitiu token (HTTP {exc.code}) — normalmente é permissão "
            f"que o App pede e a instalação ainda não aceitou. Reveja o acesso em "
            f"https://github.com/settings/installations.") from exc

    return concessao["token"], slug
