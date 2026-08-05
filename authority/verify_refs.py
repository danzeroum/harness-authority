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
    # Contagem MÍNIMA, e ela é separada do code owner por uma razão que só apareceu ao ver a
    # configuração real: `require_code_owner_review: true` com
    # `required_approving_review_count: 0` é uma combinação representável, e o que ela exige
    # na prática é ambíguo. Cobrar as duas remove a ambiguidade — "exige review" e "exige
    # review DE ALGUÉM" são frases diferentes.
    "branch_minimo_de_aprovacoes": 1,
    "branch_proibe_force_push": True,
    "bypass_deve_ser_vazio": True,
}


# Condições que dependem de GENTE, não de configuração — e a distinção custou um repositório
# congelado para ser aprendida.
#
# O `CODEOWNERS` do alvo já dizia, por escrito, que exigir review de code owner num repositório de
# um dono só não acrescenta revisor: o GitHub não deixa aprovar o próprio PR, então a regra tranca
# a main para a única pessoa que pode destrancá-la. "Não é lacuna a fechar — é aritmética." Este
# verificador exigiu assim mesmo, o dono executou, e nada mais pôde ser integrado.
#
# A autoridade continua REPORTANDO essas condições: deixar de vê-las seria a autoridade fingindo
# que o repositório está melhor do que está. O que muda é o efeito — elas não impedem o atestado,
# porque exigir o impossível transforma "o atestado nunca sai" em "ninguém lê o laudo".
#
# E a data é TRAVA, não comentário: passado o prazo, a observação vira lacuna e volta a bloquear.
# Uma dispensa sem vencimento é uma dispensa permanente com outro nome.
OBSERVACOES_DATADAS = {
    "BRANCH-SEM-CODE-OWNER": {
        "ate": "2026-11-03",
        "risco": "RISK-CHANGE-002",
        "porque": "não há revisor humano independente: o único colaborador é também o autor de "
                  "todas as propostas. Exigir aprovação aqui trancaria a main para a única pessoa "
                  "que pode destrancá-la — quatro olhos exigem duas pessoas.",
    },
    "BRANCH-SEM-APROVACAO-EXIGIDA": {
        "ate": "2026-11-03",
        "risco": "RISK-CHANGE-002",
        "porque": "mesma aritmética: uma contagem mínima de aprovações só é satisfazível por "
                  "alguém que não seja o autor.",
    },
}


# --------------------------------------------------------------------------------------
# Núcleo puro
# --------------------------------------------------------------------------------------

def classificar(achados: list[dict], *, hoje: datetime | None = None,
                observacoes: dict | None = None) -> list[dict]:
    """Marca cada achado como `lacuna` (bloqueia o atestado) ou `observacao` (só registra).

    Função à parte, e pura, para que a regra de dispensa seja legível de fora: quem audita esta
    autoridade precisa conseguir ver QUAIS achados foram dispensados, POR QUE e ATÉ QUANDO, sem ler
    o fluxo do CLI.
    """
    tabela = OBSERVACOES_DATADAS if observacoes is None else observacoes
    agora = hoje or datetime.now(timezone.utc)
    saida = []
    for a in achados:
        regra = tabela.get(a["codigo"])
        vencida = regra and datetime.fromisoformat(regra["ate"] + "T00:00:00+00:00") < agora
        if regra and not vencida:
            saida.append({**a, "classe": "observacao", "dispensada_ate": regra["ate"],
                          "risco": regra["risco"], "dispensa_porque": regra["porque"]})
        else:
            saida.append({**a, "classe": "lacuna",
                          **({"dispensa_venceu_em": regra["ate"]} if vencida else {})})
    return saida


def bloqueantes(achados: list[dict]) -> list[dict]:
    return [a for a in achados if a.get("classe", "lacuna") == "lacuna"]


def config_digest(exigidas: dict, observacoes: dict | None = None) -> str:
    """Digest do padrão APLICADO — exigências E dispensas.

    As dispensas entram de propósito: um atestado emitido sob "há uma pessoa só" e um emitido sob
    "há revisor independente" descrevem repositórios diferentes, e precisam ser distinguíveis por
    quem os consome. Sem isso, afrouxar a régua seria invisível no produto dela.
    """
    tabela = OBSERVACOES_DATADAS if observacoes is None else observacoes
    canonico = json.dumps({"exigidas": exigidas, "dispensas": tabela},
                          sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonico.encode("utf-8")).hexdigest()


def _cobre(ruleset: dict, tag_glob: str) -> bool:
    inclui = ((ruleset.get("conditions") or {}).get("ref_name") or {}).get("include") or []
    return any(i in ("~ALL", "refs/tags/**", f"refs/tags/{tag_glob}") for i in inclui)


def _cobre_branch(ruleset: dict, branch: str) -> bool:
    inclui = ((ruleset.get("conditions") or {}).get("ref_name") or {}).get("include") or []
    return any(i in ("~ALL", "~DEFAULT_BRANCH", "refs/heads/**", f"refs/heads/{branch}")
               for i in inclui)


def _protecao_por_ruleset(rulesets: list[dict], exigidas: dict) -> tuple[list[dict], bool]:
    """A `main` protegida por RULESET. Devolve (lacunas, havia_ruleset).

    Existe porque a primeira versão deste verificador só olhava
    `GET /branches/{b}/protection` — a API CLÁSSICA — e essa responde 404 quando a branch está
    protegida por ruleset. Rodando contra o alvo real, ele acusou BRANCH-SEM-PROTECAO numa branch
    que está protegida, e mandaria o dono criar proteção clássica duplicando o ruleset existente.

    Um verificador que aponta a lacuna errada é pior que um que não aponta nada: o primeiro é
    ignorado, o segundo faz alguém trabalhar no lugar errado e sair convencido de ter consertado.
    """
    branch = exigidas["branch"]
    cobrem = [r for r in rulesets
              if r.get("target") == "branch" and r.get("enforcement") == "active"
              and _cobre_branch(r, branch)]
    if not cobrem:
        return [], False

    lacunas: list[dict] = []
    for rs in cobrem:
        nome = rs.get("name") or f"ruleset:{rs.get('id')}"
        regras = {r.get("type"): (r.get("parameters") or {}) for r in (rs.get("rules") or [])}

        aprovacoes = (regras.get("pull_request") or {}).get("required_approving_review_count")
        if "pull_request" in regras and (aprovacoes or 0) < exigidas["branch_minimo_de_aprovacoes"]:
            lacunas.append({
                "codigo": "BRANCH-SEM-APROVACAO-EXIGIDA", "alvo": nome,
                "detalhe": f"o ruleset exige pull request mas aceita {aprovacoes or 0} "
                           f"aprovação(ões) — um PR pode ser integrado pelo próprio autor sem que "
                           f"ninguém tenha olhado. Exigir PR sem exigir aprovação move o trabalho "
                           f"de lugar sem acrescentar um par de olhos.",
            })

        if "pull_request" not in regras:
            lacunas.append({
                "codigo": "BRANCH-SEM-REVIEW", "alvo": nome,
                "detalhe": "o ruleset não exige pull request — sem isso, um push direto atravessa "
                           "toda a governança declarada.",
            })
        elif exigidas["branch_exige_review_de_code_owner"] and not regras["pull_request"].get(
                "require_code_owner_review"):
            lacunas.append({
                "codigo": "BRANCH-SEM-CODE-OWNER", "alvo": nome,
                "detalhe": "o ruleset exige pull request, mas não review de CODE OWNER — é o elo "
                           "que faz protected_paths significar alguma coisa; sem ele, qualquer "
                           "aprovador serve para mudar um fiscal.",
            })

        if exigidas["branch_proibe_force_push"] and "non_fast_forward" not in regras:
            lacunas.append({
                "codigo": "BRANCH-FORCE-PUSH", "alvo": nome,
                "detalhe": "o ruleset não bloqueia force push — histórico reescrevível torna "
                           "qualquer âncora por commit uma afirmação sobre conteúdo que pode ter "
                           "mudado.",
            })

        if exigidas["bypass_deve_ser_vazio"] and rs.get("bypass_actors"):
            lacunas.append({
                "codigo": "BRANCH-BYPASS-NAO-VAZIO", "alvo": nome,
                "detalhe": "bypass list não-vazia — quem pode bypassar atravessa a revisão, e a "
                           "trava passa a valer só para quem não precisaria dela.",
            })
    return lacunas, True


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

    # ---- eixo de BRANCH: a main é protegida, por QUALQUER um dos dois mecanismos? -----
    #
    # São dois, e confundi-los custou um falso positivo contra o alvo real: `ruleset` e a
    # `branch protection` clássica. `GET /branches/{b}/protection` responde 404 quando a branch
    # está protegida por ruleset — a ausência na API clássica não é ausência de proteção.
    por_ruleset, havia_ruleset = _protecao_por_ruleset(rulesets, exigidas)
    if havia_ruleset:
        return classificar(lacunas + por_ruleset)

    if not protection:
        lacunas.append({
            "codigo": "BRANCH-SEM-PROTECAO", "alvo": branch,
            "detalhe": "a branch não tem ruleset ATIVO nem branch protection clássica, e o "
                       "harness.yaml do alvo declara CODEOWNERS + branch protection como o fiscal "
                       "REAL dos protected_paths.",
        })
        return classificar(lacunas)

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

    return classificar(lacunas)


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
            # `conforme` fala do que BLOQUEIA. As observações aparecem ao lado, nunca somem — a
            # autoridade não pode ficar mais silenciosa por ter dispensado alguma coisa.
            "conforme": not bloqueantes(lacunas),
            "lacunas": bloqueantes(lacunas),
            "observacoes": [a for a in lacunas if a.get("classe") == "observacao"],
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
        # TAG e BRANCH. Filtrar só `tag` aqui foi o que cegou a primeira versão para a proteção
        # da main por ruleset — e produziu um BRANCH-SEM-PROTECAO falso contra o alvo real.
        if rs.get("target") not in ("tag", "branch"):
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

    impeditivas = bloqueantes(lacunas)
    for o in [a for a in lacunas if a.get('classe') == 'observacao']:
        print(f"• observação (dispensada até {o['dispensada_ate']}, {o['risco']}): "
              f"[{o['codigo']}] {o['alvo']}", file=sys.stderr)
    if impeditivas:
        print(f"✗ {args.repo}: {len(impeditivas)} lacuna(s) — nenhum atestado emitido:", file=sys.stderr)
        for l in impeditivas:
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
