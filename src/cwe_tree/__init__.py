import csv
import os

from ._entities import CweNode
from ._forest import CweForest

# Define `__all__` to specify the public API of the module
__all__ = ["query", "CweForest", "CweNode"]

def _get_data_path(filename: str) -> str:
    """Returns absolute path to a data file."""
    base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, "data", filename)

def _load_data() -> CweForest:
    """Loads CWE data from CSVs into a new CweForest instance."""
    forest = CweForest()
    nodes_path = _get_data_path("nodes.csv")
    rels_path = _get_data_path("rels.csv")

    if not os.path.exists(nodes_path) or not os.path.exists(rels_path):
        raise FileNotFoundError(f"CWE data files not found in {os.path.dirname(nodes_path)}")

    # Read `nodes.csv`
    with open(nodes_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            forest._add_node(row["id"], row["name"], row["abstract"], row["layer"])

    # Read `rels.csv`
    with open(rels_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            forest._add_edge(row["source"], row["target"])

    return forest

# Create a `CweForest` instance and load data immediately when the module is imported
query: CweForest = _load_data()
