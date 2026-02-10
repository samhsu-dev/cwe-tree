from typing import override
import json
from typing import Optional, Set
from cpg2py import AbcGraphQuerier, AbcEdgeQuerier, Storage
from ._node import CweNode

class CweEdge(AbcEdgeQuerier):
    """
    Represents a relationship between two CWE nodes.
    """
    pass

class CweTree(AbcGraphQuerier[CweNode, CweEdge]):
    """
    Represents a CWE Tree, which contains CWE nodes and their relationships.
    Uses cpg2py for graph storage and query capabilities.

    This class manages:
    - Creating and storing CWE nodes via Storage.
    - Establishing parent-child relationships between CWE nodes.
    - Providing utility functions for retrieving metadata and relationships.
    """

    def __init__(self):
        """ Initializes a CWE Tree with internal storage. """
        super().__init__(Storage())
        self._roots = []

    @override
    def node(self, whose_id_is: str) -> Optional[CweNode]:
        """
        Retrieves a CWE node by its ID.
        Required by AbcGraphQuerier.
        """
        whose_id_is = self._normalize_cwe(whose_id_is)
        if not self.storage.contains_node(whose_id_is):
            return None
        return CweNode(self.storage, whose_id_is)

    @override
    def edge(self, fid: str, tid: str, eid: str) -> Optional[CweEdge]:
        """
        Retrieves a CWE edge.
        Required by AbcGraphQuerier.
        """
        if not self.storage.contains_edge((fid, tid, eid)):
            return None
        return CweEdge(self.storage, fid, tid, eid)

    def _normalize_cwe(self, cwe_id: str) -> str:
        """
        Normalizes a CWE ID to ensure consistency.
        """
        return f"CWE-{cwe_id}" if not cwe_id.startswith("CWE-") else cwe_id

    def _add_node(self, cwe_id: str, name: str, abstract: str, layer: str):
        """
        Adds a CWE node to the tree storage.
        """
        cwe_id = self._normalize_cwe(cwe_id)

        # Create node if it doesn't already exist
        if not self.storage.contains_node(cwe_id):
            self.storage.add_node(cwe_id)
        
        # Ensure layer is a JSON string for storage if it's a dict
        layer_val = layer
        if isinstance(layer, dict):
            layer_val = json.dumps(layer)
        
        # Set properties
        props = {
            "name": name,
            "abstract": abstract,
            "layer": layer_val
        }
        self.storage.set_node_props(cwe_id, props)

    def _add_edge(self, parent_id: str, child_id: str):
        """
        Establishes a parent-child relationship between two CWE nodes.
        Edge flows from Parent to Child with type "CHILD".
        """
        parent_id, child_id = self._normalize_cwe(parent_id), self._normalize_cwe(child_id)
        edge_id = "CHILD"

        # Ensure both nodes exist before creating a relationship (Storage checks this internally usually, but good to be safe)
        if self.storage.contains_node(parent_id) and self.storage.contains_node(child_id):
            edge_key = (parent_id, child_id, edge_id)
            if not self.storage.contains_edge(edge_key):
                self.storage.add_edge(edge_key)

    def get_node(self, cwe_id: str) -> Optional[CweNode]:
        """
        Retrieves a CWE node by its ID.

        Args:
            cwe_id: The unique CWE identifier to retrieve.

        Returns:
             The requested CWE node, or None if it does not exist.
        """
        return self.node(cwe_id)

    def get_parents(self, cwe_id: str) -> Set[CweNode]:
        """
        Retrieves the parents of a given CWE node.

        Args:
            cwe_id: The CWE ID whose parents should be retrieved.

        Returns:
            A set of parent CWE IDs.
        """
        node = self.get_node(cwe_id)
        if not node:
            return set()
        
        return set(self.prev(node))

    def get_children(self, cwe_id: str) -> Set[CweNode]:
        """
        Retrieves the children of a given CWE node.

        Args:
            cwe_id: The CWE ID whose children should be retrieved.

        Returns:
            A set of child CWE IDs.
        """
        node = self.get_node(cwe_id)
        if not node:
            return set()
        
        return set(self.succ(node))

    def get_layer(self, cwe_id: str) -> dict:
        """
        Retrieves the layer information for a given CWE node.

        Args:
            cwe_id: The CWE ID whose layer should be retrieved.

        Returns:
            A dictionary representing the layer mapping (e.g., { "CWE-284": 2 }).
        """
        node = self.get_node(cwe_id)
        return node.layer if node else {}

    def get_metadata(self, cwe_id: str) -> Optional[dict]:
        """
        Retrieves metadata for a given CWE node, including relationships.

        Args:
            cwe_id: The CWE ID whose metadata should be retrieved.

        Returns:
            A dictionary containing metadata about the CWE node, including
            parents and children lists. Returns None if node not found.
        """
        node = self.get_node(cwe_id)
        if not node:
            return None
        
        metadata = node.get_metadata()
        metadata["parents"] = [n.cwe_id for n in self.get_parents(cwe_id)]
        metadata["children"] = [n.cwe_id for n in self.get_children(cwe_id)]
        return metadata

    def get_roots(self) -> list:
        """
        Retrieves all root nodes in the CWE tree.

        Root nodes are nodes that have no parents.

        Returns:
            list: A list of CweNode instances that have no parents.
        """
        if self._roots: 
            return self._roots
        for node in self.nodes():
            if not any(self.prev(node)):
                self._roots.append(node)
        return self._roots
