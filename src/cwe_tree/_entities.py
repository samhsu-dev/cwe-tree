"""CweNode and CweEdge representations."""

import json
from typing import Any, Dict

from cpg2py import AbcEdgeQuerier, AbcNodeQuerier, Storage


class CweEdge(AbcEdgeQuerier):
    """Represents a relationship between two CWE nodes."""


class CweNode(AbcNodeQuerier):
    """Represents a single CWE (Common Weakness Enumeration) node.

    Attributes:
        storage: Reference to the underlying graph storage.

    A CWE node encapsulates:
        - Unique CWE identifier
        - Weakness name and description
        - Abstraction level (Class, Base, Variant)
        - Layer mapping indicating depth in root hierarchies
        - Parent-child relationships
    """

    def __init__(self, storage: Storage, nid: str) -> None:
        """Initialize a CWE node.

        Args:
            storage: The graph storage backend.
            nid: The node identifier.
        """
        super().__init__(storage, nid)
        self.storage = storage

    @property
    def cwe_id(self) -> str:
        """Retrieves the unique CWE identifier.

        Returns:
            The CWE ID (e.g., "CWE-732").
        """
        return str(self.node_id)

    @property
    def name(self) -> str:
        """Retrieves the name/description of the weakness.

        Returns:
            The descriptive name of the CWE, or empty string if not available.
        """
        name_value = self.get_property("name")
        return str(name_value) if name_value is not None else ""

    @property
    def abstract(self) -> str:
        """Retrieves the abstraction type of the weakness.

        Returns:
            The abstraction type (e.g., "Class", "Base", "Variant"),
            or empty string if not available.
        """
        abstract_value = self.get_property("abstract")
        return str(abstract_value) if abstract_value is not None else ""

    @property
    def layer(self) -> Dict[str, int]:
        """Retrieves the layer mapping for this node.

        The layer mapping indicates the depth of this node within different
        CWE root hierarchies.

        Returns:
            Dictionary mapping root CWE IDs to depth levels.
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
        """Retrieves the intrinsic metadata of this CWE node.

        Returns only properties stored directly on the node, without
        traversing relationships.

        Returns:
            Dictionary containing 'id', 'name', 'abstract', and 'layer'.
        """
        return {
            "id": self.cwe_id,
            "name": self.name,
            "abstract": self.abstract,
            "layer": self.layer,
        }
