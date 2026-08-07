"""Mordidas da ENTREGA do atestado — a parte que ficou 19h dizendo sucesso sem ter entregado.

O verificador estava certo e o atestado era válido; o que falhou foi a última perna. `publicar.py`
abria o PR, imprimia "atestado proposto" e voltava 0, e ninguém tinha como distinguir isso de uma
renovação que fechou. O PR #55 viveu 19h nesse verde e o molde bloqueou a si mesmo.

Estes testes atacam o núcleo puro, sem rede: cada `mergeable_state` que a API pode devolver tem uma
decisão nomeada, e a decisão errada aqui é invisível em produção até o carimbo vencer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from authority.publicar import (  # noqa: E402
    INDETERMINADO,
    PRONTO,
    RESSINCRONIZAR,
    capacidade_de_automerge,
    decidir_acao,
)


# --------------------------------------------------------------------------------------
# A proposta está integrável — e "integrável" não é "mergeada"
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("estado", ["clean", "blocked", "unstable", "has_hooks"])
def test_estados_integraveis_nao_pedem_acao(estado):
    """`blocked` é o estado NORMAL logo após abrir: faltam os checks obrigatórios.

    Tratá-lo como problema faria a autoridade alarmar todo dia contra o portão do molde
    trabalhando. Quem espera os checks é o auto-merge nativo, não este script.
    """
    acao, _ = decidir_acao(estado=estado, ja_ressincronizou=False)
    assert acao == PRONTO


# --------------------------------------------------------------------------------------
# A corrida: a `main` se move entre a montagem do commit e a abertura do PR
# --------------------------------------------------------------------------------------

def test_proposta_atrasada_ressincroniza_uma_vez():
    acao, motivo = decidir_acao(estado="behind", ja_ressincronizou=False)
    assert acao == RESSINCRONIZAR
    assert "atrasada" in motivo


def test_segunda_corrida_no_mesmo_instante_desiste_com_alarme():
    """O limite é a decisão, não uma limitação.

    Um laço de re-sincronização contra uma `main` que recebe merges continuamente é uma corrida
    perdida de antemão: cada volta gasta cota e devolve verde. Desistir com alarme deixa o atestado
    vencer, e o vencimento é o sinal que o molde já sabe ler.
    """
    acao, motivo = decidir_acao(estado="behind", ja_ressincronizou=True)
    assert acao == INDETERMINADO
    assert "laço" in motivo


def test_o_laco_e_impossivel_por_construcao():
    """Não há terceira volta: `behind` + já-ressincronizou não devolve RESSINCRONIZAR jamais.

    Este teste existe porque a proibição do laço é uma propriedade do desenho, e propriedade que
    ninguém exercita é promessa. Se alguém trocar a condição por um contador, isto acusa.
    """
    for _ in range(5):
        acao, _ = decidir_acao(estado="behind", ja_ressincronizou=True)
        assert acao != RESSINCRONIZAR


# --------------------------------------------------------------------------------------
# Bordas: conflito real, rascunho, estado que este código não conhece
# --------------------------------------------------------------------------------------

def test_conflito_real_nao_e_atraso_e_nao_se_resolve_re_sincronizando():
    """`dirty` ⇒ indeterminado, jamais força.

    A autoridade PROPÕE. Resolver conflito no molde seria escrever por cima de alguém, que é o
    poder que este repositório não tem por desenho — o mesmo motivo pelo qual entrega por PR e não
    por push.
    """
    acao, motivo = decidir_acao(estado="dirty", ja_ressincronizou=False)
    assert acao == INDETERMINADO
    assert "conflito real" in motivo


def test_estado_desconhecido_e_indeterminado_nunca_otimista():
    """O fiscal perguntou e não entendeu a resposta. Isso não é "está tudo bem"."""
    acao, _ = decidir_acao(estado="unknown", ja_ressincronizou=False)
    assert acao == INDETERMINADO
    acao, _ = decidir_acao(estado="um_estado_que_a_api_inventou_amanha", ja_ressincronizou=False)
    assert acao == INDETERMINADO


def test_rascunho_nao_e_promovido_pela_autoridade():
    acao, _ = decidir_acao(estado="draft", ja_ressincronizou=False)
    assert acao == INDETERMINADO


# --------------------------------------------------------------------------------------
# A trava sobre a caixa — a dependência que não aparece em arquivo nenhum
# --------------------------------------------------------------------------------------

def test_capacidade_presente_nao_gera_achado():
    assert capacidade_de_automerge({"allow_auto_merge": True}) is None


@pytest.mark.parametrize("info", [
    {"allow_auto_merge": False},
    {},                                 # o campo nem veio na resposta
    {"allow_auto_merge": None},
    {"allow_auto_merge": "true"},       # string não é True, e aqui a distinção é a trava
])
def test_capacidade_ausente_vira_achado_com_a_acao_exata(info):
    """Foi ESTE o buraco do #55, e ele saiu verde.

    `gh pr merge --auto` falhou com `Auto merge is not allowed for this repository`, a CP-037
    avisou e seguiu — corretamente, no escopo dela. Um aviso diário que não muda nada é um aviso
    que se aprende a pular. O achado nomeia a caixa e o caminho até ela.
    """
    motivo = capacidade_de_automerge(info)
    assert motivo is not None
    assert "Allow auto-merge" in motivo
    assert "Settings" in motivo
