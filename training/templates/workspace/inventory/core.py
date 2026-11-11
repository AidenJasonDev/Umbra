"""Tiny inventory model used as the Umbra lab workspace."""

from dataclasses import dataclass


@dataclass
class Item:
    name: str
    price: float
    qty: int


def total_value(items):
    """Total stock value: price times quantity, summed over all items."""
    return round(sum(i.price for i in items), 2)


def find_item(items, name):
    for i in items:
        if i.name.lower() == name.lower():
            return i
    return None


SAMPLE = [
    Item("widget", 2.50, 10),
    Item("gadget", 12.00, 3),
    Item("doohickey", 0.75, 40),
]
