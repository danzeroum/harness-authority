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


def test_o_atestado_expira_e_a_folga_vem_da_cadencia():
    """O excedente continua sendo a decisão; o que mudou foi contra o QUE ele é medido.

    Antes: 25h fixas para um cron diário — uma hora de folga. A premissa era que um cron diário
    dispara diariamente, e o campo a desmentiu: o run declarado para 06:17Z de 06/08 saiu às
    08:51Z (2h34 tarde) e o de 07/08 não saiu. Uma hora de folga contra duas e meia de atraso é
    margem negativa, e o vencimento passou a medir a pontualidade do agendador em vez da saúde da
    proteção — o molde bloqueou por isso duas vezes.

    Agora a folga é DERIVADA da cadência. O que este teste protege não é o número: é que o
    atestado continue EXPIRANDO, e dentro de uma janela que um verificador realmente parado não
    atravessa. Janela folgada demais transformaria "o verificador parou" em silêncio, que é o
    estado que este repositório existe para impedir.
    """
    agora = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)
    a = vr.montar_atestado(repository="o/r", exigidas=vr.EXIGIDAS_PADRAO, rulesets=[_ruleset()],
                           issuer_identity="x", agora=agora)["attestation"]
    janela = datetime.fromisoformat(a["expires_at"]) - datetime.fromisoformat(a["checked_at"])

    assert janela == vr.VALIDADE, "o atestado precisa carregar a validade declarada, não outra"

    # A RELAÇÃO, não o número: a janela cobre os ciclos tolerados e sobra alguma folga. Escrever
    # "+ 2h" aqui foi o que obrigou a editar este teste ao afrouxar a cadência na CP-046 — a
    # terceira vez que um número copiado se voltou contra quem o copiou.
    ciclos = vr.CADENCIA * vr.CICLOS_TOLERADOS
    assert janela > ciclos, (
        "sem folga SOBRE os ciclos tolerados, o último ciclo perdido e o vencimento coincidem e a "
        "corrida decide")
    assert janela - ciclos < vr.CADENCIA, (
        "a folga é margem para atraso do agendador, não um ciclo extra disfarçado — se ela crescer "
        "além de um intervalo, o número de ciclos tolerados na prática deixa de ser o declarado")

    # O TETO NÃO MORA MAIS AQUI, e a mudança é de fronteira, não de rigor: quem autoriza a validade
    # máxima é o repositório vigiado, em `harness.yaml:external_audit.cadence`, e
    # `audit_governance.py::check_attestation_cadence` a confere contra este carimbo. Uma autoridade
    # que declarasse o próprio teto estaria se autorizando — exatamente o que a camada externa
    # existe para impedir.


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
    # DERIVADO da validade, nunca um "ontem" literal: com a cadência afrouxada na CP-046 um
    # carimbo de dois dias atrás passou a estar VÁLIDO, e o teste reprovava por medir o calendário
    # em vez de medir a trava.
    ha_muito = datetime.now(timezone.utc) - vr.VALIDADE - timedelta(hours=1)
    escrever(vr.montar_atestado(repository="danzeroum/project", exigidas=vr.EXIGIDAS_PADRAO,
                                rulesets=[_ruleset()], issuer_identity="x", agora=ha_muito))
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
def test_EMISSOR_NAO_AUTORIZADO_AGORA_BLOQUEIA(molde_ligado):
    """A lacuna fechou, e este teste é o registro de que fechou — invertido, não apagado.

    O que ele dizia até 05/08/2026: *`check_external_attestation` valida existência, legibilidade,
    schema e validade; o campo `issuer` é EXIGIDO pelo schema e NUNCA COMPARADO com nada — hoje um
    atestado emitido por qualquer identidade passa, inclusive um escrito à mão num PR do próprio
    molde.* Ele afirmava esse comportamento de propósito e prometia virar vermelho no dia em que a
    emenda `authorized_issuer` entrasse no molde.

    Entrou (CP-036 / ADR-028 lá), ele ficou vermelho, e a inversão é a confirmação. Apagá-lo e
    escrever um teste novo teria o mesmo efeito no CI e perderia a única coisa que ele carregava:
    a data em que esta autoridade deixou de produzir "alguém atestou" e passou a produzir "quem
    devia atestou".

    O achado tem de ser o PRÓPRIO, não um genérico de invalidez: "isto envelheceu" e "alguém
    escreveu isto à mão" pedem investigações diferentes, e só a segunda manda olhar o histórico do
    arquivo e quem o tocou.
    """
    raiz, escrever = molde_ligado
    escrever(vr.montar_atestado(repository="danzeroum/project", exigidas=vr.EXIGIDAS_PADRAO,
                                rulesets=[_ruleset()],
                                issuer_identity="quem-quiser-escrever-isto",
                                issuer_kind="external_service"))
    chaves = [a["id"] for a in _achados_de_conformidade(raiz) if a["severity"] != "info"]
    assert "FIND-EXT-AUDIT-EMISSOR-NAO-AUTORIZADO" in chaves, chaves


# --------------------------------------------------------------------------------------
# OBSERVAÇÃO vs LACUNA — a distinção que custou um repositório congelado
# --------------------------------------------------------------------------------------

def _sem_code_owner() -> list[dict]:
    rs = _ruleset_branch(rules=[
        {"type": "pull_request", "parameters": {"require_code_owner_review": False,
                                                "required_approving_review_count": 0}},
        {"type": "non_fast_forward"}])
    return _verificar(rulesets=[_ruleset(), rs], protection={})


def test_a_falta_de_revisor_e_OBSERVACAO_e_nao_bloqueia():
    """O CODEOWNERS do alvo já dizia por escrito: exigir review de code owner num repositório de
    um dono só não acrescenta revisor — tranca a main para a única pessoa que pode destrancá-la.
    Este verificador exigiu assim mesmo, o dono executou, e nada mais pôde ser integrado.

    A autoridade continua VENDO a condição. O que mudou é o efeito.
    """
    achados = _sem_code_owner()
    assert {a["codigo"] for a in achados} == {"BRANCH-SEM-CODE-OWNER",
                                             "BRANCH-SEM-APROVACAO-EXIGIDA"}
    assert all(a["classe"] == "observacao" for a in achados)
    assert vr.bloqueantes(achados) == []


def test_a_observacao_carrega_prazo_risco_e_motivo():
    """Quem audita a AUTORIDADE precisa ver o que foi dispensado, por quê e até quando — sem ler
    o fluxo do CLI."""
    a = next(x for x in _sem_code_owner() if x["codigo"] == "BRANCH-SEM-CODE-OWNER")
    assert a["dispensada_ate"] == "2026-11-03"
    assert a["risco"] == "RISK-CHANGE-002"
    assert "quatro olhos exigem duas pessoas" in a["dispensa_porque"]


def test_passado_o_prazo_a_observacao_VOLTA_a_bloquear():
    """A data é TRAVA, não comentário. Uma dispensa sem vencimento é uma dispensa permanente com
    outro nome."""
    depois = datetime(2026, 11, 4, tzinfo=timezone.utc)
    reclassificados = vr.classificar(
        [{"codigo": "BRANCH-SEM-CODE-OWNER", "alvo": "x", "detalhe": "y"}], hoje=depois)
    assert reclassificados[0]["classe"] == "lacuna"
    assert reclassificados[0]["dispensa_venceu_em"] == "2026-11-03"
    assert vr.bloqueantes(reclassificados)


def test_lacuna_real_continua_bloqueando_ao_lado_da_observacao():
    """A dispensa é por CÓDIGO, não uma anistia geral: tags desprotegidas seguem impedindo."""
    rs = _ruleset_branch(rules=[
        {"type": "pull_request", "parameters": {"require_code_owner_review": False,
                                                "required_approving_review_count": 0}},
        {"type": "non_fast_forward"}])
    achados = _verificar(rulesets=[rs], protection={})   # sem ruleset de TAG
    assert {a["codigo"] for a in vr.bloqueantes(achados)} == {"TAG-SEM-RULESET"}


def test_o_digest_muda_quando_a_DISPENSA_muda():
    """Um atestado emitido sob 'há uma pessoa só' e um emitido sob 'há revisor independente'
    descrevem repositórios diferentes. Sem isso no digest, afrouxar a régua seria invisível no
    produto dela."""
    assert vr.config_digest(vr.EXIGIDAS_PADRAO, {}) != vr.config_digest(vr.EXIGIDAS_PADRAO)


def test_o_laudo_separa_as_duas_classes():
    laudo = vr.montar_laudo(repository="o/r", lacunas=_sem_code_owner(),
                            exigidas=vr.EXIGIDAS_PADRAO)["laudo"]
    assert laudo["conforme"] is True          # nada BLOQUEIA
    assert laudo["lacunas"] == []
    assert len(laudo["observacoes"]) == 2     # ...e nada foi escondido


def test_so_com_observacoes_o_atestado_E_emitido(tmp_path, monkeypatch):
    """O ponta a ponta da correção: o estado real do alvo hoje passa a emitir atestado."""
    rs = _ruleset_branch(rules=[
        {"type": "pull_request", "parameters": {"require_code_owner_review": False,
                                                "required_approving_review_count": 0}},
        {"type": "non_fast_forward"}])
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setattr(vr, "coletar", lambda *a, **k: ([_ruleset(), rs], {}))
    laudo, atestado = tmp_path / "l.json", tmp_path / "a.json"
    assert vr.main(["--repo", "o/r", "--laudo", str(laudo), "--atestado", str(atestado)]) == 0
    assert atestado.exists()
    assert len(json.loads(laudo.read_text())["laudo"]["observacoes"]) == 2


# --------------------------------------------------------------------------------------
# O manifesto do App — permissões declaradas, não digitadas
# --------------------------------------------------------------------------------------

def test_o_manifesto_pede_o_minimo_e_nada_alem():
    """Permissão marcada a mais numa página web não avisa ninguém. Declarada em arquivo, ela
    aparece em diff — e é por isso que o manifesto existe."""
    from authority import criar_app

    m = json.loads(criar_app.MANIFESTO.read_text(encoding="utf-8"))
    assert m["default_permissions"] == {
        "metadata": "read",          # ler o repositório
        "administration": "read",    # ler rulesets e branch protection — NUNCA write
        "contents": "write",         # escrever o atestado na branch da proposta
        "pull_requests": "write",    # abrir o PR de entrega
    }
    assert m["public"] is False
    assert m["default_events"] == []


def test_o_manifesto_nao_declara_hook_attributes():
    """Ausente, e não `{"active": false}` — que foi a primeira tentativa e o GitHub recusou.

    Quando `hook_attributes` existe, o GitHub exige `url` DENTRO dele, e a recusa vem como
    `Error "url" wasn't supplied` — que soa como se faltasse o `url` de topo, que estava lá. Sem a
    chave, não há webhook e não há campo obrigatório a preencher. Declarar menos foi o conserto.
    """
    from authority import criar_app

    m = json.loads(criar_app.MANIFESTO.read_text(encoding="utf-8"))
    assert "hook_attributes" not in m


def test_a_autoridade_nao_pede_ADMINISTRATION_write():
    """A distinção que separa auditor de administrador: quem pode MUDAR o ruleset não pode
    testemunhar sobre ele. Um auditor com poder de escrita sobre o que audita é um auditor que
    pode consertar o que deveria reportar."""
    from authority import criar_app

    m = json.loads(criar_app.MANIFESTO.read_text(encoding="utf-8"))
    assert m["default_permissions"]["administration"] == "read"


def test_a_pagina_nao_depende_de_javascript():
    """O que está no `value` é o que o navegador envia.

    A primeira versão montava o campo por script, como o exemplo da documentação do GitHub — e o
    GitHub recusou com `Error "url" wasn\'t supplied` mesmo com o `url` presente e o HTML impresso
    correto. Sintoma de manifesto que chega vazio, não de manifesto errado. Um caminho com menos
    peças tem menos lugares onde a diferença entre o visto e o enviado possa se esconder.
    """
    from authority import criar_app

    html = criar_app.montar_pagina({"name": "x", "url": "https://e.com"}, "S")
    assert "<script" not in html
    assert 'name="manifest" value="' in html
    assert "&quot;url&quot;: &quot;https://e.com&quot;" in html


def test_a_pagina_leva_o_manifesto_e_o_state():
    """O `state` é conferido na volta: sem ele, qualquer aba aberta no navegador poderia entregar
    o `code` de OUTRO App a este script, e o secret gravado seria a credencial de algo que você
    não criou."""
    from authority import criar_app

    html = criar_app.montar_pagina({"name": "x"}, "ESTADO-123")
    assert "state=ESTADO-123" in html
    assert "https://github.com/settings/apps/new" in html


def test_o_gitignore_nao_engole_a_saida_do_workflow():
    """O padrão `laudo*.json` sem barra inicial casava `atestados/laudo.json` — a saída do
    workflow. O `git add` não adicionava nada, não reclamava, e o passo ficava verde sem ter
    registrado laudo algum.

    Os padrões dos arquivos de trabalho local ficam ANCORADOS na raiz.
    """
    linhas = [l.strip() for l in (RAIZ / ".gitignore").read_text(encoding="utf-8").splitlines()]
    for nome in ("regras", "atestado", "laudo"):
        assert f"/{nome}*.json" in linhas, f"{nome}*.json precisa de barra inicial"
        assert f"{nome}*.json" not in linhas
