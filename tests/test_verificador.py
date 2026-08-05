"""Mordidas da autoridade externa.

Três níveis, e o de baixo não substitui o de cima:

  UNIDADE     o núcleo puro acusa a lacuna certa a partir de fixtures construídas à mão.
  INTEGRAÇÃO  o atestado emitido valida contra o schema REAL do molde, lido do checkout.
  SISTEMA     o molde com `external_audit.enabled: true` CONSOME o atestado e reage.

O terceiro é o que importa mais, e é onde o `<recomendacao>` mandou olhar: um verificador correto
cujo atestado o consumidor ignora é autoridade de papel. Autoridade de fato é o consumidor mudando
de cor.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from authority import verify_refs as vr  # noqa: E402

MOLDE = Path(os.environ.get("MOLDE_ROOT", "/home/user/project"))
SCHEMA = MOLDE / "harness/schemas/protection-attestation.schema.json"
precisa_do_molde = pytest.mark.skipif(
    not SCHEMA.exists(), reason=f"checkout do molde ausente em {MOLDE} (defina MOLDE_ROOT)")


# --------------------------------------------------------------------------------------
# Fixtures de configuração real da API
# --------------------------------------------------------------------------------------

def _ruleset(**kw) -> dict:
    base = {
        "id": 4242, "name": "tags imóveis", "target": "tag", "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/tags/v*"]}},
        "rules": [{"type": t} for t in ("deletion", "non_fast_forward", "update")],
        "bypass_actors": [],
    }
    base.update(kw)
    return base


def _protection(**kw) -> dict:
    base = {
        "required_pull_request_reviews": {"require_code_owner_reviews": True},
        "allow_force_pushes": {"enabled": False},
    }
    base.update(kw)
    return base


def _verificar(**kw) -> list[dict]:
    args = {"rulesets": [_ruleset()], "protection": _protection(),
            "exigidas": vr.EXIGIDAS_PADRAO}
    args.update(kw)
    return vr.verificar(**args)


def _codigos(lacunas: list[dict]) -> set[str]:
    return {l["codigo"] for l in lacunas}


# --------------------------------------------------------------------------------------
# UNIDADE — o núcleo puro
# --------------------------------------------------------------------------------------

def test_configuracao_conforme_nao_gera_lacuna():
    """O par obrigatório da mordida. Um verificador que só acusa é desligado por quem trabalha —
    e desligado ele não atesta nada."""
    assert _verificar() == []


def test_tags_sem_ruleset_e_a_lacuna_de_hoje():
    """O estado real do danzeroum/project em 05/08/2026, e a razão desta tarefa existir."""
    l = _verificar(rulesets=[])
    assert _codigos(l) == {"TAG-SEM-RULESET"}
    assert "recusa do CLIENTE" in l[0]["detalhe"]


@pytest.mark.parametrize("faltando", ["deletion", "non_fast_forward", "update"])
def test_regra_de_tag_ausente_e_acusada(faltando):
    regras = [{"type": t} for t in ("deletion", "non_fast_forward", "update") if t != faltando]
    l = _verificar(rulesets=[_ruleset(rules=regras)])
    assert _codigos(l) == {"TAG-REGRA-AUSENTE"}
    assert faltando in l[0]["detalhe"]


def test_creation_no_ruleset_de_tag_e_LACUNA_nao_virtude():
    """A regra a mais que quebra o alvo. `creation` trancaria o workflow_dispatch de release do
    molde — o único caminho legítimo de publicação — e o resultado seria alguém desligar o ruleset
    inteiro para conseguir publicar. Exigir demais e exigir de menos falham no mesmo lugar."""
    l = _verificar(rulesets=[_ruleset(rules=[{"type": t} for t in
                                             ("deletion", "non_fast_forward", "update", "creation")])])
    assert _codigos(l) == {"TAG-REGRA-PROIBIDA"}
    assert "workflow_dispatch" in l[0]["detalhe"]


def test_bypass_nao_vazio_e_acusado():
    l = _verificar(rulesets=[_ruleset(bypass_actors=[{"actor_id": 5}])])
    assert _codigos(l) == {"TAG-BYPASS-NAO-VAZIO"}


def test_ruleset_desativado_nao_protege():
    assert _codigos(_verificar(rulesets=[_ruleset(enforcement="disabled")])) == {"TAG-SEM-RULESET"}


def test_ruleset_que_nao_cobre_a_familia_nao_protege():
    fora = {"ref_name": {"include": ["refs/tags/beta-*"]}}
    assert _codigos(_verificar(rulesets=[_ruleset(conditions=fora)])) == {"TAG-SEM-RULESET"}


def test_branch_sem_protecao_para_de_perguntar():
    """Sem proteção alguma, perguntar 'exige code owner?' produziria ruído sobre a mesma causa."""
    assert _codigos(_verificar(protection={})) == {"BRANCH-SEM-PROTECAO"}


# ---- os dois mecanismos de proteção de branch, e o falso positivo que eles custaram -----

def _ruleset_branch(**kw) -> dict:
    base = {
        "id": 777, "name": "main protegida", "target": "branch", "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
        "rules": [
            {"type": "pull_request", "parameters": {"require_code_owner_review": True,
                                                    "required_approving_review_count": 1}},
            {"type": "non_fast_forward"},
        ],
        "bypass_actors": [],
    }
    base.update(kw)
    return base


def test_branch_protegida_por_RULESET_sem_protecao_classica_e_conforme():
    """O falso positivo que o alvo real revelou, agora em teste.

    `GET /branches/{b}/protection` responde 404 quando a branch está protegida por RULESET — são
    dois mecanismos distintos, e a ausência na API clássica não é ausência de proteção. A primeira
    versão acusou BRANCH-SEM-PROTECAO numa main protegida, e mandaria o dono criar proteção
    clássica duplicando o ruleset existente.

    Um verificador que aponta a lacuna ERRADA é pior que um que não aponta nada: o primeiro é
    ignorado, o segundo faz alguém trabalhar no lugar errado e sair convencido de ter consertado.
    """
    assert _verificar(rulesets=[_ruleset(), _ruleset_branch()], protection={}) == []


def test_ruleset_de_branch_sem_code_owner_e_acusado():
    rs = _ruleset_branch(rules=[{"type": "pull_request",
                                 "parameters": {"required_approving_review_count": 1}},
                                {"type": "non_fast_forward"}])
    assert _codigos(_verificar(rulesets=[_ruleset(), rs], protection={})) == {
        "BRANCH-SEM-CODE-OWNER"}


def test_pull_request_exigido_com_ZERO_aprovacoes_e_acusado():
    """A configuração REAL do alvo em 05/08/2026, e o achado que a contagem revelou.

    `pull_request` presente, `required_approving_review_count: 0`. O PR é obrigatório e pode ser
    integrado pelo próprio autor sem que ninguém tenha olhado — exigir PR sem exigir aprovação
    move o trabalho de lugar sem acrescentar um par de olhos. É representável, e por isso precisa
    ser cobrado separado de `require_code_owner_review`.
    """
    rs = _ruleset_branch(rules=[
        {"type": "pull_request", "parameters": {"require_code_owner_review": False,
                                                "required_approving_review_count": 0}},
        {"type": "non_fast_forward"}])
    assert _codigos(_verificar(rulesets=[_ruleset(), rs], protection={})) == {
        "BRANCH-SEM-APROVACAO-EXIGIDA", "BRANCH-SEM-CODE-OWNER"}


def test_ruleset_de_branch_sem_pull_request_e_acusado():
    rs = _ruleset_branch(rules=[{"type": "non_fast_forward"}])
    assert _codigos(_verificar(rulesets=[_ruleset(), rs], protection={})) == {"BRANCH-SEM-REVIEW"}


def test_ruleset_de_branch_sem_bloqueio_de_force_push_e_acusado():
    rs = _ruleset_branch(rules=[{"type": "pull_request",
                                 "parameters": {"require_code_owner_review": True,
                                                "required_approving_review_count": 1}}])
    assert _codigos(_verificar(rulesets=[_ruleset(), rs], protection={})) == {"BRANCH-FORCE-PUSH"}


def test_ruleset_de_branch_com_bypass_e_acusado():
    rs = _ruleset_branch(bypass_actors=[{"actor_id": 1}])
    assert _codigos(_verificar(rulesets=[_ruleset(), rs], protection={})) == {
        "BRANCH-BYPASS-NAO-VAZIO"}


def test_ruleset_de_branch_desativado_nao_conta_e_cai_na_classica():
    """Desativado é como não existir — e aí a pergunta volta para a proteção clássica."""
    rs = _ruleset_branch(enforcement="disabled")
    assert _codigos(_verificar(rulesets=[_ruleset(), rs], protection={})) == {
        "BRANCH-SEM-PROTECAO"}
    assert _verificar(rulesets=[_ruleset(), rs], protection=_protection()) == []


def test_review_sem_code_owner_e_acusado():
    p = _protection(required_pull_request_reviews={"require_code_owner_reviews": False})
    assert _codigos(_verificar(protection=p)) == {"BRANCH-SEM-CODE-OWNER"}


def test_force_push_permitido_e_acusado():
    p = _protection(allow_force_pushes={"enabled": True})
    assert _codigos(_verificar(protection=p)) == {"BRANCH-FORCE-PUSH"}


def test_as_lacunas_se_acumulam():
    """Quem vai consertar precisa ver as três de uma vez, não descobrir a terceira em três rodadas."""
    p = _protection(required_pull_request_reviews=None, allow_force_pushes={"enabled": True})
    assert _codigos(_verificar(rulesets=[], protection=p)) == {
        "TAG-SEM-RULESET", "BRANCH-SEM-REVIEW", "BRANCH-FORCE-PUSH"}


@pytest.mark.parametrize("ausente", ["rulesets", "protection"])
def test_o_nucleo_puro_recusa_decidir_indeterminacao(ausente):
    """A trava que impede o modo de falha mais caro: devolver 'sem lacunas' a partir de ausência
    de resposta. Verde por silêncio é indistinguível de verde por conformidade."""
    with pytest.raises(ValueError, match="não decide indeterminação"):
        _verificar(**{ausente: None})


def test_o_digest_muda_quando_a_exigencia_muda():
    """É o que permite dizer 'foi ESTA regra que passou'. Sem isso, um atestado antigo seria lido
    como se falasse da exigência nova."""
    outra = dict(vr.EXIGIDAS_PADRAO, tag_regras_exigidas=["deletion"])
    assert vr.config_digest(vr.EXIGIDAS_PADRAO) != vr.config_digest(outra)


# --------------------------------------------------------------------------------------
# INTEGRAÇÃO — o atestado contra o schema REAL do molde
# --------------------------------------------------------------------------------------

@precisa_do_molde
def test_o_atestado_valida_contra_o_schema_do_molde():
    """Contra o schema do CHECKOUT, nunca contra uma cópia daqui: uma cópia derivaria no primeiro
    dia em que o molde mudasse o contrato, e os dois lados ficariam convencidos de estar certos."""
    a = vr.montar_atestado(repository="danzeroum/project", exigidas=vr.EXIGIDAS_PADRAO,
                           rulesets=[_ruleset()], issuer_identity="harness-authority")
    assert vr.validar_contra_schema(a, str(SCHEMA)) == []


@precisa_do_molde
def test_o_atestado_tem_os_campos_que_o_schema_exige_com_os_nomes_dele():
    """`ruleset_ref`, `verifier_version`, `config_digest` — os nomes do schema, não os da prosa que
    pediu o verificador. Quem reprova é o schema."""
    exigidos = set(json.loads(SCHEMA.read_text(encoding="utf-8"))
                   ["properties"]["attestation"]["required"])
    a = vr.montar_atestado(repository="danzeroum/project", exigidas=vr.EXIGIDAS_PADRAO,
                           rulesets=[_ruleset()], issuer_identity="x")["attestation"]
    assert exigidos <= set(a)
    assert a["issuer"] == {"identity": "x", "kind": "github_app"}


def test_a_validade_e_de_25h_para_um_cron_diario():
    """O excedente é a decisão: uma execução perdida faz o atestado EXPIRAR em vez de continuar
    valendo. Janela folgada transformaria 'o verificador parou' em silêncio."""
    agora = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)
    a = vr.montar_atestado(repository="o/r", exigidas=vr.EXIGIDAS_PADRAO, rulesets=[_ruleset()],
                           issuer_identity="x", agora=agora)["attestation"]
    assert datetime.fromisoformat(a["expires_at"]) - datetime.fromisoformat(a["checked_at"]) \
        == timedelta(hours=25)


def test_ruleset_ref_e_referencia_e_nao_copia():
    a = vr.montar_atestado(repository="danzeroum/project", exigidas=vr.EXIGIDAS_PADRAO,
                           rulesets=[_ruleset()], issuer_identity="x")["attestation"]
    assert "4242" in a["ruleset_ref"]
    assert "non_fast_forward" not in a["ruleset_ref"]


def test_o_laudo_carrega_o_que_o_atestado_nao_pode():
    """O schema do atestado é `additionalProperties: false` e não tem campo para lacunas — por
    desenho, porque atestado é afirmação positiva. O laudo é onde a lacuna vive, com data."""
    lacunas = _verificar(rulesets=[])
    laudo = vr.montar_laudo(repository="danzeroum/project", lacunas=lacunas,
                            exigidas=vr.EXIGIDAS_PADRAO)
    assert laudo["laudo"]["conforme"] is False
    assert laudo["laudo"]["lacunas"][0]["codigo"] == "TAG-SEM-RULESET"
    assert laudo["laudo"]["config_digest"] == vr.config_digest(vr.EXIGIDAS_PADRAO)


# --------------------------------------------------------------------------------------
# CAMADA DE REDE — 403 é indeterminação, nunca lacuna
# --------------------------------------------------------------------------------------

def test_403_na_api_e_indeterminacao(monkeypatch):
    def recusa(*a, **k):
        raise urllib.error.HTTPError("u", 403, "Forbidden", {}, None)

    monkeypatch.setattr(vr.urllib.request, "urlopen", recusa)
    with pytest.raises(vr.Indeterminado, match="403"):
        vr.coletar("danzeroum/project", "tok", vr.EXIGIDAS_PADRAO)


def test_sem_credencial_nenhum_atestado_e_emitido(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    saida = tmp_path / "atestado.json"
    codigo = vr.main(["--repo", "o/r", "--laudo", str(tmp_path / "l.json"),
                      "--atestado", str(saida)])
    assert codigo == vr.EXIT_UNVERIFIABLE
    assert not saida.exists(), "silêncio nunca carimba"


def test_lacuna_produz_laudo_e_NENHUM_atestado(tmp_path, monkeypatch):
    """A regra que separa este verificador de um que emitisse 'atestado com ressalvas' — um
    'sim, mas' que o consumidor lê como sim."""
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setattr(vr, "coletar", lambda *a, **k: ([], _protection()))
    laudo, atestado = tmp_path / "l.json", tmp_path / "a.json"
    assert vr.main(["--repo", "o/r", "--laudo", str(laudo), "--atestado", str(atestado)]) == 1
    assert json.loads(laudo.read_text())["laudo"]["lacunas"]
    assert not atestado.exists()


def test_estado_limpo_emite_atestado(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setattr(vr, "coletar", lambda *a, **k: ([_ruleset()], _protection()))
    laudo, atestado = tmp_path / "l.json", tmp_path / "a.json"
    assert vr.main(["--repo", "o/r", "--laudo", str(laudo), "--atestado", str(atestado)]) == 0
    assert json.loads(atestado.read_text())["attestation"]["repository"] == "o/r"
    assert json.loads(laudo.read_text())["laudo"]["conforme"] is True


# --------------------------------------------------------------------------------------
# SISTEMA — o molde consome, e é aqui que papel vira autoridade
# --------------------------------------------------------------------------------------

@pytest.fixture
def molde_ligado(tmp_path):
    """Cópia do molde com `external_audit.enabled: true`. Devolve (raiz, escrever_atestado)."""
    destino = tmp_path / "molde"
    shutil.copytree(MOLDE, destino,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", "workspace", "*.pyc"))

    # A troca é NA CHAVE, ancorada em início de linha — e a lição está aqui, em comentário, porque
    # ela custou um verde falso: o primeiro "enabled: false" do arquivo está num COMENTÁRIO da
    # linha 38, explicando por que a flag fica desligada. Um replace ingênuo trocou o comentário,
    # a fixture continuou "funcionando", e o teste do atestado válido passou — não porque o
    # consumo aprovou, mas porque a autoridade seguia DESLIGADA e o único achado era `info`.
    # Uma fixture que não confere o que promete produz exatamente o estado que este repositório
    # existe para impedir.
    caminho = destino / "harness/harness.yaml"
    doc = caminho.read_text(encoding="utf-8")
    caminho.write_text(doc.replace("\n  enabled: false", "\n  enabled: true", 1), encoding="utf-8")
    assert yaml.safe_load(caminho.read_text(encoding="utf-8"))["external_audit"]["enabled"] is True

    def escrever(atestado: dict | None) -> None:
        alvo = destino / "harness/state/protection-attestation.json"
        alvo.parent.mkdir(parents=True, exist_ok=True)
        if atestado is None:
            alvo.unlink(missing_ok=True)
        else:
            alvo.write_text(json.dumps(atestado, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")

    return destino, escrever


def _achados_de_conformidade(raiz: Path) -> list[dict]:
    """Roda o fiscal REAL do molde, no processo dele, e devolve os achados."""
    r = subprocess.run(
        [sys.executable, "-c",
         "import sys, json; sys.path.insert(0, 'ci');"
         "import audit_governance as ag, harness_lib as hl;"
         "f = hl.Findings();"
         "ag.check_external_attestation(hl.read_yaml('harness/harness.yaml'),"
         " hl.read_yaml('governance/risk-register.yaml'), f);"
         "print(json.dumps(f.items))"],
        cwd=raiz, capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


@precisa_do_molde
def test_atestado_valido_deixa_o_molde_verde(molde_ligado):
    """O aceite central: com a autoridade LIGADA e um atestado válido, o consumo não bloqueia."""
    raiz, escrever = molde_ligado
    escrever(vr.montar_atestado(repository="danzeroum/project", exigidas=vr.EXIGIDAS_PADRAO,
                                rulesets=[_ruleset()], issuer_identity="harness-authority"))
    bloqueantes = [a for a in _achados_de_conformidade(raiz) if a["severity"] != "info"]
    assert not bloqueantes, bloqueantes


@precisa_do_molde
def test_atestado_expirado_bloqueia(molde_ligado):
    """Não é warning. Atestado sem validade seria carimbo eterno sobre configuração que pode ter
    mudado dez minutos depois da visita."""
    raiz, escrever = molde_ligado
    ontem = datetime.now(timezone.utc) - timedelta(days=2)
    escrever(vr.montar_atestado(repository="danzeroum/project", exigidas=vr.EXIGIDAS_PADRAO,
                                rulesets=[_ruleset()], issuer_identity="x", agora=ontem))
    chaves = [a["id"] for a in _achados_de_conformidade(raiz)]
    assert "FIND-EXT-AUDIT-ATESTADO-EXPIRADO" in chaves, chaves


@precisa_do_molde
def test_atestado_ausente_bloqueia_igual_a_expirado(molde_ligado):
    """É o que faz o cron perdido se resolver sozinho: sem execução, sem atestado novo; o anterior
    vence em 25h e o consumo bloqueia sem ninguém precisar perceber."""
    raiz, escrever = molde_ligado
    escrever(None)
    chaves = [a["id"] for a in _achados_de_conformidade(raiz)]
    assert "FIND-EXT-AUDIT-SEM-ATESTADO" in chaves, chaves


@precisa_do_molde
def test_atestado_fora_do_schema_bloqueia(molde_ligado):
    raiz, escrever = molde_ligado
    a = vr.montar_atestado(repository="danzeroum/project", exigidas=vr.EXIGIDAS_PADRAO,
                           rulesets=[_ruleset()], issuer_identity="x")
    a["attestation"].pop("config_digest")
    escrever(a)
    chaves = [x["id"] for x in _achados_de_conformidade(raiz)]
    assert "FIND-EXT-AUDIT-ATESTADO-INVALIDO" in chaves, chaves


@precisa_do_molde
def test_EMISSOR_NAO_AUTORIZADO_AINDA_PASSA_e_isto_esta_documentado(molde_ligado):
    """A borda que o `<contexto>` mandou deixar vermelha e documentada — em forma de teste.

    `check_external_attestation` valida existência, legibilidade, schema e validade. O campo
    `issuer` é EXIGIDO pelo schema e NUNCA COMPARADO com nada. Hoje, um atestado emitido por
    qualquer identidade passa — inclusive um escrito à mão num PR do próprio molde.

    Este teste afirma o comportamento ATUAL de propósito. Ele vira vermelho no dia em que a
    emenda `authorized_issuer` entrar no molde, e ficar vermelho será a confirmação de que a
    lacuna fechou. Um teste que descreve o buraco é mais honesto que um `skip` que o esconde.
    """
    raiz, escrever = molde_ligado
    escrever(vr.montar_atestado(repository="danzeroum/project", exigidas=vr.EXIGIDAS_PADRAO,
                                rulesets=[_ruleset()],
                                issuer_identity="quem-quiser-escrever-isto",
                                issuer_kind="external_service"))
    bloqueantes = [a for a in _achados_de_conformidade(raiz) if a["severity"] != "info"]
    assert not bloqueantes, (
        "o molde passou a recusar emissor não declarado — a emenda authorized_issuer entrou, "
        "e este teste deve ser invertido")
