"""CweNode and CweEdge representations."""

import json
from typing import Any, Dict

from cpg2py import AbcEdgeQuerier, AbcNodeQuerier, Storage


class CweEdge(AbcEdgeQuerier):
    """Represents a relationship between two CWE nodes."""


class CweNode(AbcNodeQuerier):
    """
    Represents a single CWE (Common Weakness Enumeration) node.

    A CWE node contains:
    - A unique CWE ID.
    - A name describing the weakness.
    - An abstract type (e.g., Class, Base, Variant).
    - A layer mapping indicating its depth in different root trees.
    - Parent-child relationships to track CWE dependencies.
    """

    def __init__(self, storage: Storage, nid: str) -> None:
        super().__init__(storage, nid)
        self.storage = storage

    @property
    def cwe_id(self) -> str:
        """Returns the unique CWE identifier."""
        return str(self.node_id)  # AbcNodeQuerier uses 'node_id' property

    @property
    def name(self) -> str:
        """Returns the name/description of the weakness."""
        name_value = self.get_property("name")
        return str(name_value) if name_value is not None else ""

    @property
    def abstract(self) -> str:
        """Returns the abstraction type of the weakness."""
        abstract_value = self.get_property("abstract")
        return str(abstract_value) if abstract_value is not None else ""

    @property
    def layer(self) -> Dict[str, int]:
        """
        Returns the layer mapping for this node.

        The layer mapping indicates the depth of this node within different
        CWE root hierarchies.
        """
        layer_str = self.get_property("layer")
        if not layer_str:
            return {}
        try:
            result: Dict[str, Any] = json.loads(str(layer_str))
            return result
        except json.JSONDecodeError:
            return {}

    def get_metadata(self) -> Dict[str, Any]:
        """Returns the intrinsic metadata of this CWE node."""
        return {
            "id": self.cwe_id,
            "name": self.name,
            "abstract": self.abstract,
            "layer": self.layer,
        }
