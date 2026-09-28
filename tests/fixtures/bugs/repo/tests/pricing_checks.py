from src.pricing import price_in_currency


def test_missing_currency_defaults_to_eur():
    market = {"rate": 1}
    assert market["currency"] == "EUR"


def helper(x, acc=[]):
    return acc
