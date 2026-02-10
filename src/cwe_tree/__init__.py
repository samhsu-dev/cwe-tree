import csv
import os
from typing import Optional

from ._node import CweNode
from ._tree import CweTree

# Define `__all__` to specify the public API of the module
__all__ = ["query", "CweTree", "CweNode"]

def _get_data_path(filename: str) -> str:
    """Returns absolute path to a data file."""
    base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, "data", filename)

def _load_data() -> CweTree:
    """Loads CWE data from CSVs into a new CweTree instance."""
    tree = CweTree()
    nodes_path = _get_data_path("nodes.csv")
    rels_path = _get_data_path("rels.csv")

    if not os.path.exists(nodes_path) or not os.path.exists(rels_path):
        # Fallback or raise? Workflow says "Fail fast".
        # But for now, if data is missing, it might be better to return empty tree or raise FileNotFoundError.
        # Given it's package data, it SHOULD exist.
        raise FileNotFoundError(f"CWE data files not found in {os.path.dirname(nodes_path)}")

    # Read `nodes.csv`
    with open(nodes_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tree._add_node(
                row["id"], 
                row["name"], 
                row["abstract"], 
                row["layer"]
            )

    # Read `rels.csv`
    with open(rels_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tree._add_edge(row["source"], row["target"])

    return tree

# Create a `CweTree` instance and load data immediately when the module is imported
query: CweTree = _load_data()
