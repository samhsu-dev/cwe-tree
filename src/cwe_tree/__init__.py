"""CWE Tree module for querying CWE forests."""

import csv
import os
from typing import Any

from ._entities import CweNode
from ._forest import CweForest

__all__ = ["query", "CweForest", "CweNode"]


def _get_data_path(filename: str) -> str:
    """Return absolute path to a data file."""
    base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, "data", filename)


def _load_data() -> CweForest:
    """Load CWE data from CSVs into a new CweForest instance."""
    forest = CweForest()
    nodes_path = _get_data_path("nodes.csv")
    rels_path = _get_data_path("rels.csv")

    if not os.path.exists(nodes_path) or not os.path.exists(rels_path):
        raise FileNotFoundError(f"CWE data files not found in {os.path.dirname(nodes_path)}")

    with open(nodes_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row is None:
                continue
            forest._add_node(row["id"], row["name"], row["abstract"], row["layer"])

    with open(rels_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row is None:
                continue
            forest._add_edge(row["source"], row["target"])

    return forest


query: CweForest = _load_data()
