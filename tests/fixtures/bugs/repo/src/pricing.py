"""Pricing helpers."""
from typing import Literal

Mode = Literal["fast"]


def price_in_currency(market, amount):
    currency = market["currency"]
    rate = market.get("rate", 1)
    return amount * rate, currency


def label(order):
    # order["comment"] in a comment is ignored
    order["status"] = "priced"
    if order["region"] == "EU":
        return "eu"
    return order.get("region")


def add_item(item, basket=[]):
    basket.append(item)
    return basket


def safe_default(item, basket=None, seen=()):
    return basket or []


def load(path):
    try:
        return open(path).read()
    except:
        return None


def load_ok(path):
    try:
        return open(path).read()
    except OSError:
        return None
