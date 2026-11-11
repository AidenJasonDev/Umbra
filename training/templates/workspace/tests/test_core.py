import unittest

from inventory.core import SAMPLE, Item, find_item, total_value


class TestCore(unittest.TestCase):
    def test_total_value(self):
        self.assertEqual(total_value(SAMPLE), 91.0)

    def test_total_value_empty(self):
        self.assertEqual(total_value([]), 0)

    def test_find_item(self):
        self.assertEqual(find_item(SAMPLE, "GADGET").price, 12.00)
        self.assertIsNone(find_item(SAMPLE, "sprocket"))

    def test_item_fields(self):
        i = Item("x", 1.0, 2)
        self.assertEqual((i.name, i.price, i.qty), ("x", 1.0, 2))


if __name__ == "__main__":
    unittest.main()
