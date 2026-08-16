from types import SimpleNamespace

from cipherfault.indicators import repeated_operand_indicators


class Value:
    def isConstant(self):
        return False

    def __str__(self):
        return "same-varnode"


def test_repeated_iv_is_an_indicator_question_not_a_verified_fact():
    anchors = [
        SimpleNamespace(primitive=None, func_name="encrypt", call_addr=address, operands={"iv": Value()})
        for address in ("1000", "1010")
    ]

    indicators = repeated_operand_indicators(anchors)

    assert len(indicators) == 1
    assert indicators[0].tier == "INDICATOR"
    assert indicators[0].primitive == "AES"
    assert indicators[0].analyst_question.endswith("?")


def test_rng_quality_stays_an_analyst_question():
    from cipherfault.indicators import rng_quality_indicator

    indicator = rng_quality_indicator(
        SimpleNamespace(primitive="ML-KEM", func_name="encap", call_addr="2000"),
        SimpleNamespace(origin="getrandom"),
        "randomness",
    )

    assert indicator.tier == "INDICATOR"
    assert "runtime?" in indicator.analyst_question
