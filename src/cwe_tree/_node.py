import json
from cpg2py import AbcNodeQuerier

class CweNode(AbcNodeQuerier):
    """
    Represents a single CWE (Common Weakness Enumeration) node in the CWE hierarchy.

    A CWE node contains:
    - A unique CWE ID.
    - A name describing the weakness.
    - An abstract type (e.g., Class, Base, Variant).
    - A layer mapping indicating its depth in different root trees.
    - Parent-child relationships to track CWE dependencies.
    """
    
    def __init__(self, storage, nid):
        super().__init__(storage, nid)
        self.storage = storage

    @property
    def cwe_id(self) -> str:
        """
        Returns the unique CWE identifier.

        Returns:
            str: The CWE ID (e.g., "CWE-732").
        """
        return self.node_id  # AbcNodeQuerier uses 'node_id' property
        
    @property
    def name(self) -> str:
        """
        Returns the name/description of the weakness.

        Returns:
            str: The descriptive name of the CWE.
        """
        return self.get_property("name")

    @property
    def abstract(self) -> str:
        """
        Returns the abstraction type of the weakness.

        Returns:
            str: The abstraction type (e.g., "Class", "Base", "Variant").
        """
        return self.get_property("abstract")

    @property
    def layer(self) -> dict:
        """
        Returns the layer mapping for this node.

        The layer mapping indicates the depth of this node within different
        CWE root hierarchies.

        Returns:
            dict: A dictionary mapping root CWE IDs to depth levels.
        """
        layer_str = self.get_property("layer")
        try:
            return json.loads(layer_str) if layer_str else {}
        except json.JSONDecodeError:
            return {}

    def get_metadata(self) -> dict:
        """
        Returns the intrinsic metadata of this CWE node.

        Unlike `CweTree.get_metadata()`, this method returns only the properties
        stored directly on the node, without traversing relationships.

        Returns:
            dict: A dictionary containing 'id', 'name', 'abstract', and 'layer'.
        """
        return {
            "id": self.cwe_id,
            "name": self.name,
            "abstract": self.abstract,
            "layer": self.layer,
        }
