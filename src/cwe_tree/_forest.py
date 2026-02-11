"""
CweForest is a subclass of AbcGraphQuerier that represents a CWE Forest.
It is used to store and query CWE nodes and their relationships.
"""
import json
from typing import override, Optional, Set
from cpg2py import AbcGraphQuerier, Storage
from ._entities import CweNode, CweEdge

class CweForest(AbcGraphQuerier[CweNode, CweEdge]):
    """
    Represents a CWE Forest, which contains CWE nodes and their relationships.
    Uses cpg2py for graph storage and query capabilities.

    This class manages:
    - Creating and storing CWE nodes via Storage.
    - Establishing parent-child relationships between CWE nodes.
    - Providing utility functions for retrieving metadata and relationships.
    
    The forest structure supports multiple independent trees rooted at different nodes.
    """

    def __init__(self):
        """ Initializes a CWE Forest with internal storage. """
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
        Adds a CWE node to the forest storage.
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

    def get_root_nodes(self) -> list:
        """
        Retrieves all root nodes in the CWE forest.

        Root nodes are nodes that have no parents. This represents
        the forest structure where multiple independent trees can exist.

        Returns:
            list: A list of CweNode instances with no parents.
        """
        if self._roots: 
            return self._roots
        for node in self.nodes():
            if not any(self.prev(node)):
                self._roots.append(node)
        return self._roots

    def _show_node(self, node: CweNode, indent: int = 0, visited: Optional[Set] = None) -> None:
        """
        Recursively prints a CWE node and its children with tree-like indentation.

        Args:
            node: The CweNode to display.
            indent: Current indentation level (default: 0).
            visited: Set of already-visited node IDs to prevent cycles (default: None).
        """
        if visited is None:
            visited = set()

        node_id = node.cwe_id
        if node_id in visited:
            return

        visited.add(node_id)

        # Format the output with tree-like structure
        prefix = "├── " if indent > 0 else ""
        spaces = "│   " * (indent - 1) if indent > 0 else ""
        
        print(f"{spaces}{prefix}{node.cwe_id}: {node.name}")

        # Recursively display children
        children = self.get_children(node_id)
        for child in children:
            self._show_node(child, indent + 1, visited)

    def show(self, cwe_id: Optional[str] = None) -> None:
        """
        Visualizes the CWE forest structure starting from a node or all roots.

        If a CWE ID is provided, displays the subtree rooted at that node.
        If no CWE ID is provided, displays all root nodes and their subtrees.

        Args:
            cwe_id: Optional CWE ID to start visualization from (default: None).
        """
        if cwe_id:
            node = self.get_node(cwe_id)
            if node:
                self._show_node(node)
            else:
                print(f"Node {cwe_id} not found.")
        else:
            roots = self.get_root_nodes()
            if roots:
                for root in roots:
                    self._show_node(root)
            else:
                print("No root nodes found in the forest.")
