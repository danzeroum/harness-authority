#!/usr/bin/env python3
"""Autoridade externa de proteção de refs — audita danzeroum/project DE FORA.

Por que este arquivo não mora no repositório que ele fiscaliza, e essa é a decisão inteira:

  A camada local do molde (`ci/verify_protection.py`) confere as mesmas coisas e NÃO BASTA. Ela
  mora no mesmo repositório que fiscaliza: um PR com privilégio suficiente remove o passo e a
  asserção que o vigia no mesmo commit, e o CI fica verde porque a trava saiu junto com quem
  reclamaria dela. É circular por construção, e nenhuma quantidade de código lá resolve.

  Aqui não é circular. Uma mudança no molde não alcança este arquivo. É a diferença entre o
  restaurante imprimir o próprio laudo sanitário e a prefeitura emitir o dela.

TRÊS DECISÕES QUE MERECEM ESTAR NO TOPO:

  NÚCLEO PURO. `verificar` não abre socket. Recebe os rulesets e a proteção JÁ LIDOS e devolve
  lacunas. Quem tem a rede é o CLI. Não é preferência de estilo: um verificador que faz I/O
  confunde "a trava está desligada" com "não consegui olhar", e as duas conclusões exigem reações
  opostas. É o princípio (h) do plano do molde, aplicado aqui pela mesma razão.

  SILÊNCIO NUNCA CARIMBA. Sem credencial, com a API fora do ar, ou com 403 na leitura dos
  rulesets, NENHUM atestado é emitido e o job sai com código de indeterminação. Um atestado é uma
  afirmação positiva; não conseguir verificar não é uma afirmação.

  ATESTADO SÓ DE ESTADO LIMPO. Havendo lacuna, sai LAUDO e não sai atestado. O atestado afirma "as
  travas exigidas estão ligadas"; com tags desprotegidas essa frase é falsa, e um atestado com
  ressalva seria um "sim, mas" que o consumidor lê como sim.

Uso:
  python authority/verify_refs.py --repo danzeroum/project \\
      --laudo laudo.json [--atestado atestado.json] [--schema CAMINHO]
Saída: 0 limpo (atestado emitido) · 1 lacuna (laudo, sem atestado) · 3 indeterminação (nada).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

VERIFIER_VERSION = "1.0"

# 25h para um cron diário, e o excedente é a decisão: uma execução perdida faz o atestado
# anterior EXPIRAR em vez de continuar valendo. Uma janela folgada transformaria "o verificador
# parou de rodar" em silêncio, que é exatamente o estado que este repositório existe para impedir.
VALIDADE = timedelta(hours=25)

EXIT_LACUNA = 1
EXIT_UNVERIFIABLE = 3

# O que se exige do alvo. Fica aqui, versionado, e seu digest entra no atestado — é o que permite
# dizer "foi ESTA regra que passou", em vez de "passou alguma regra num momento qualquer".
EXIGIDAS_PADRAO = {
    "branch": "main",
    "tag_glob": "v*",
    # deletion + non_fast_forward + update impedem MOVER e APAGAR. `creation` é proibida de
    # propósito: exigi-la trancaria o workflow_dispatch de release do molde, que é o único caminho
    # legítimo de publicação. Uma trava que impede o trabalho legítimo é desligada por quem tem
    # trabalho a fazer.
    "tag_regras_exigidas": ["deletion", "non_fast_forward", "update"],
    "tag_regras_proibidas": ["creation"],
    "branch_exige_review_de_code_owner": True,
    "branch_proibe_force_push": True,
    "bypass_deve_ser_vazio": True,
}


# --------------------------------------------------------------------------------------
# Núcleo puro
# --------------------------------------------------------------------------------------

def config_digest(exigidas: dict) -> str:
    """Digest da configuração AVALIADA, não da encontrada. Muda a exigência, muda o digest — e um
    atestado antigo deixa de poder ser lido como se falasse da regra nova."""
    canonico = json.dumps(exigidas, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonico.encode("utf-8")).hexdigest()


def _cobre(ruleset: dict, tag_glob: str) -> bool:
    inclui = ((ruleset.get("conditions") or {}).get("ref_name") or {}).get("include") or []
    return any(i in ("~ALL", "refs/tags/**", f"refs/tags/{tag_glob}") for i in inclui)


def verificar(*, rulesets: list[dict], protection: dict, exigidas: dict) -> list[dict]:
    """As lacunas entre o exigido e o real. Lista vazia = tudo que se exige está ligado.

    Devolve dicionários e não frases porque o chamador precisa AGRUPAR e COMPARAR: o laudo de hoje
    contra o de ontem, para dizer "esta lacuna é nova". Texto livre não se compara.

    `None` não entra aqui. Indeterminação é decisão do chamador, que é quem sabe se a resposta
    faltou por 403, por timeout ou por falta de credencial — e as três pedem mensagens diferentes.
    """
    if rulesets is None or protection is None:
        raise ValueError(
            "verificar() não decide indeterminação: chame-a só com dados lidos. Devolver 'sem "
            "lacunas' a partir de ausência de resposta é como um verde falso nasce.")

    lacunas: list[dict] = []
    tag_glob = exigidas["tag_glob"]
    branch = exigidas["branch"]

    # ---- eixo de TAGS: a âncora das releases é imóvel? -------------------------------
    cobrem = [r for r in rulesets
              if r.get("target") == "tag" and r.get("enforcement") == "active"
              and _cobre(r, tag_glob)]

    if not cobrem:
        lacunas.append({
            "codigo": "TAG-SEM-RULESET",
            "alvo": f"refs/tags/{tag_glob}",
            "detalhe": "nenhum ruleset de tag ATIVO cobre estas refs — a âncora das releases "
                       "depende de a tag não se mover, e nada impede que ela se mova. O `git push` "
                       "sem --force do workflow é recusa do CLIENTE; a trava é do servidor.",
        })
    for rs in cobrem:
        nome = rs.get("name") or f"ruleset:{rs.get('id')}"
        tipos = {r.get("type") for r in (rs.get("rules") or [])}
        faltando = [t for t in exigidas["tag_regras_exigidas"] if t not in tipos]
        if faltando:
            lacunas.append({
                "codigo": "TAG-REGRA-AUSENTE", "alvo": nome,
                "detalhe": f"não exige {', '.join(faltando)} — sem essas regras a tag pode ser "
                           f"reapontada ou apagada, e todo derivado que a cita passa a afirmar "
                           f"procedência sobre conteúdo que já não está lá.",
            })
        proibidas = [t for t in exigidas["tag_regras_proibidas"] if t in tipos]
        if proibidas:
            lacunas.append({
                "codigo": "TAG-REGRA-PROIBIDA", "alvo": nome,
                "detalhe": f"exige {', '.join(proibidas)} — isto tranca o workflow_dispatch de "
                           f"release, que é o ÚNICO caminho legítimo de publicação. Uma trava que "
                           f"impede o trabalho legítimo é desligada por quem tem trabalho a fazer.",
            })
        if exigidas["bypass_deve_ser_vazio"] and rs.get("bypass_actors"):
            lacunas.append({
                "codigo": "TAG-BYPASS-NAO-VAZIO", "alvo": nome,
                "detalhe": "quem pode bypassar pode mover a tag, e a trava passa a valer só para "
                           "quem não precisaria dela.",
            })

    # ---- eixo de BRANCH: a main é protegida? -----------------------------------------
    if not protection:
        lacunas.append({
            "codigo": "BRANCH-SEM-PROTECAO", "alvo": branch,
            "detalhe": "a branch não tem proteção alguma configurada, e o harness.yaml do alvo "
                       "declara CODEOWNERS + branch protection como o fiscal REAL dos "
                       "protected_paths.",
        })
        return lacunas

    reviews = protection.get("required_pull_request_reviews")
    if not reviews:
        lacunas.append({
            "codigo": "BRANCH-SEM-REVIEW", "alvo": branch,
            "detalhe": "não exige pull request review — sem isso, um push direto atravessa toda a "
                       "governança declarada.",
        })
    elif exigidas["branch_exige_review_de_code_owner"] and not reviews.get(
            "require_code_owner_reviews"):
        lacunas.append({
            "codigo": "BRANCH-SEM-CODE-OWNER", "alvo": branch,
            "detalhe": "exige review, mas não de CODE OWNER — é o elo que faz protected_paths "
                       "significar alguma coisa; sem ele, qualquer aprovador serve para mudar um "
                       "fiscal.",
        })

    if exigidas["branch_proibe_force_push"] and protection.get(
            "allow_force_pushes", {}).get("enabled"):
        lacunas.append({
            "codigo": "BRANCH-FORCE-PUSH", "alvo": branch,
            "detalhe": "permite force push — histórico reescrevível torna qualquer âncora por "
                       "commit (target.lock, mold_release, executed_in) uma afirmação sobre "
                       "conteúdo que pode ter mudado.",
        })

    return lacunas


def ruleset_ref(*, repository: str, rulesets: list[dict], exigidas: dict) -> str:
    """Referência, nunca cópia: o conteúdo do ruleset é do lado de fora, e replicá-lo no atestado
    criaria uma segunda versão que deriva da primeira no dia seguinte."""
    ids = sorted(str(r.get("id")) for r in rulesets
                 if r.get("target") == "tag" and r.get("enforcement") == "active"
                 and _cobre(r, exigidas["tag_glob"]))
    return f"{repository}#tag-rulesets:{','.join(ids) or 'nenhum'}+branch:{exigidas['branch']}"


def montar_atestado(*, repository: str, exigidas: dict, rulesets: list[dict],
                    issuer_identity: str, issuer_kind: str = "github_app",
                    agora: datetime | None = None) -> dict:
    """O atestado, na forma que o SCHEMA DO MOLDE julga.

    Os nomes dos campos são os do schema (`ruleset_ref`, `verifier_version`, `config_digest`) e não
    os da prosa que pediu este verificador. Quem reprova é o schema; construir para a prosa
    produziria um documento que descreve bem e valida mal.
    """
    quando = agora or datetime.now(timezone.utc)
    return {
        "schema_version": "1.0",
        "metadata_version": "1.0",
        "source_of_truth": True,
        "generated_from": None,
        "attestation": {
            "repository": repository,
            "branch": exigidas["branch"],
            "checked_at": quando.isoformat(timespec="seconds"),
            "expires_at": (quando + VALIDADE).isoformat(timespec="seconds"),
            "ruleset_ref": ruleset_ref(repository=repository, rulesets=rulesets,
                                       exigidas=exigidas),
            "issuer": {"identity": issuer_identity, "kind": issuer_kind},
            "verifier_version": VERIFIER_VERSION,
            "config_digest": config_digest(exigidas),
        },
    }


def montar_laudo(*, repository: str, lacunas: list[dict], exigidas: dict,
                 agora: datetime | None = None) -> dict:
    """O registro que o atestado NÃO pode carregar.

    O schema do atestado é `additionalProperties: false` e não tem campo para lacunas — por
    desenho, porque um atestado é afirmação positiva. O laudo é onde a lacuna vive, e é ele que
    fecha RISK-EXT-001 no dia em que o dono ligar os rulesets: ele diz, com data, o que faltava.
    """
    quando = agora or datetime.now(timezone.utc)
    return {
        "schema_version": "1.0",
        "laudo": {
            "repository": repository,
            "checked_at": quando.isoformat(timespec="seconds"),
            "verifier_version": VERIFIER_VERSION,
            "config_digest": config_digest(exigidas),
            "conforme": not lacunas,
            "lacunas": lacunas,
        },
    }


# --------------------------------------------------------------------------------------
# Camada com rede — a única que sabe o que é um 403
# --------------------------------------------------------------------------------------

class Indeterminado(Exception):
    """Não foi possível olhar. Distinta de 'olhei e está errado', e é toda a diferença."""


def _api(url: str, token: str) -> object:
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": f"harness-authority/{VERIFIER_VERSION}",
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - URL montada aqui
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise Indeterminado(
                f"{url} respondeu {exc.code}: a credencial não alcança este recurso. Sem "
                f"Administration:Read no alvo não há como distinguir 'sem ruleset' de 'sem "
                f"permissão de ver' — e escolher a leitura otimista seria carimbar o silêncio."
            ) from exc
        if exc.code == 404:
            # 404 em /branches/{b}/protection significa "sem proteção" OU "sem permissão", e a API
            # não distingue. Quem chama decide; aqui devolvemos o vazio explícito.
            return None
        raise Indeterminado(f"{url} respondeu {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise Indeterminado(f"{url}: {exc}") from exc


def coletar(repository: str, token: str, exigidas: dict) -> tuple[list[dict], dict]:
    """Rulesets COM suas regras, e a proteção da branch. Levanta Indeterminado se não der."""
    lista = _api(f"https://api.github.com/repos/{repository}/rulesets?includes_parents=true", token)
    if lista is None:
        raise Indeterminado(f"{repository}: a listagem de rulesets não respondeu conteúdo")

    detalhados = []
    for rs in lista:
        if rs.get("target") != "tag":
            continue
        # Duas chamadas porque a listagem devolve resumo SEM `rules`, e decidir sobre um ruleset
        # a partir do nome dele é decidir a partir de como alguém o chamou.
        completo = _api(f"https://api.github.com/repos/{repository}/rulesets/{rs['id']}", token)
        if completo is None:
            raise Indeterminado(f"{repository}: ruleset {rs['id']} não pôde ser detalhado")
        detalhados.append(completo)

    protection = _api(
        f"https://api.github.com/repos/{repository}/branches/{exigidas['branch']}/protection",
        token)
    return detalhados, (protection or {})


def validar_contra_schema(atestado: dict, caminho_schema: str) -> list[str]:
    """Valida contra o schema REAL do molde, lido do checkout — nunca contra uma cópia local.

    Uma cópia aqui derivaria da original no primeiro dia em que o molde mudasse o schema, e este
    verificador passaria a emitir documentos que o consumidor recusa, com os dois lados
    convencidos de estarem certos.
    """
    import jsonschema

    with open(caminho_schema, encoding="utf-8") as fh:
        schema = json.load(fh)
    validador = jsonschema.Draft202012Validator(schema)
    return [f"{'/'.join(str(p) for p in e.path) or '(raiz)'}: {e.message}"
            for e in validador.iter_errors(atestado)]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Autoridade externa de proteção de refs.")
    p.add_argument("--repo", required=True)
    p.add_argument("--laudo", required=True)
    p.add_argument("--atestado")
    p.add_argument("--schema", help="protection-attestation.schema.json do checkout do molde")
    p.add_argument("--issuer", default=os.environ.get("ISSUER_IDENTITY", "harness-authority"))
    args = p.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        print("• indeterminado: sem credencial para consultar a proteção de "
              f"{args.repo}. Nenhum atestado emitido — silêncio nunca carimba.", file=sys.stderr)
        return EXIT_UNVERIFIABLE

    try:
        rulesets, protection = coletar(args.repo, token, EXIGIDAS_PADRAO)
    except Indeterminado as exc:
        print(f"• indeterminado: {exc}\n  Nenhum atestado emitido.", file=sys.stderr)
        return EXIT_UNVERIFIABLE

    lacunas = verificar(rulesets=rulesets, protection=protection, exigidas=EXIGIDAS_PADRAO)

    laudo = montar_laudo(repository=args.repo, lacunas=lacunas, exigidas=EXIGIDAS_PADRAO)
    with open(args.laudo, "w", encoding="utf-8") as fh:
        json.dump(laudo, fh, indent=2, ensure_ascii=False, sort_keys=True)
        fh.write("\n")

    if lacunas:
        print(f"✗ {args.repo}: {len(lacunas)} lacuna(s) — nenhum atestado emitido:", file=sys.stderr)
        for l in lacunas:
            print(f"  - [{l['codigo']}] {l['alvo']}: {l['detalhe']}", file=sys.stderr)
        return EXIT_LACUNA

    atestado = montar_atestado(repository=args.repo, exigidas=EXIGIDAS_PADRAO,
                               rulesets=rulesets, issuer_identity=args.issuer)
    if args.schema:
        problemas = validar_contra_schema(atestado, args.schema)
        if problemas:
            print("• indeterminado: o atestado não valida contra o schema do molde — emitir um "
                  "documento que o consumidor recusa é pior que não emitir:", file=sys.stderr)
            for m in problemas:
                print(f"  - {m}", file=sys.stderr)
            return EXIT_UNVERIFIABLE

    if args.atestado:
        with open(args.atestado, "w", encoding="utf-8") as fh:
            json.dump(atestado, fh, indent=2, ensure_ascii=False, sort_keys=True)
            fh.write("\n")
    print(f"✓ {args.repo}: proteção conforme; atestado válido até "
          f"{atestado['attestation']['expires_at']}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
