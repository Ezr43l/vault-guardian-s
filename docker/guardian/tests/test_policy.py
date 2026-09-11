import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "app"))

import floating


class PolicyTests(unittest.TestCase):
    def test_unknown_portador_never_counts_as_active(self):
        state = floating.FloatingState("instancia-1", known=False)
        self.assertFalse(state.is_active)
        self.assertFalse(state.is_node_active("nodo-1"))

    def test_only_current_portador_is_active(self):
        state = floating.FloatingState("instancia-1", known=True, portador="nodo-1")
        self.assertTrue(state.is_node_active("nodo-1"))
        self.assertFalse(state.is_node_active("nodo-2"))


if __name__ == "__main__":
    unittest.main()

