"""
CweForest is a subclass of AbcGraphQuerier that represents a CWE Forest.
It is used to store and query CWE nodes and their relationships.
"""

import json
from typing import Any, Dict, List, Optional, Set, override

from cpg2py import AbcGraphQuerier, Storage

from ._entities import CweEdge, CweNode


class CweForest(AbcGraphQuerier[CweNode, CweEdge]):
    """
    Represents a CWE Forest, which contains CWE nodes and their relationships.

    Uses cpg2py for graph storage and query capabilities.
    """

    def __init__(self) -> None:
        """Initialize a CWE Forest with internal storage."""
        super().__init__(Storage())
        self._roots: List[CweNode] = []

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
        """Normalize a CWE ID to ensure consistency."""
        return f"CWE-{cwe_id}" if not cwe_id.startswith("CWE-") else cwe_id

    def _add_node(self, cwe_id: str, name: str, abstract: str, layer: str) -> None:
        """Add a CWE node to the forest storage."""
        cwe_id = self._normalize_cwe(cwe_id)

        if not self.storage.contains_node(cwe_id):
            self.storage.add_node(cwe_id)

        layer_val: Any = layer
        if isinstance(layer, dict):
            layer_val = json.dumps(layer)

        props: Dict[str, Any] = {
            "name": name,
            "abstract": abstract,
            "layer": layer_val,
        }
        self.storage.set_node_props(cwe_id, props)

    def _add_edge(self, parent_id: str, child_id: str) -> None:
        """Establish a parent-child relationship between two CWE nodes."""
        parent_id, child_id = self._normalize_cwe(parent_id), self._normalize_cwe(child_id)
        edge_id = "CHILD"

        if self.storage.contains_node(parent_id) and self.storage.contains_node(child_id):
            edge_key = (parent_id, child_id, edge_id)
            if not self.storage.contains_edge(edge_key):
                self.storage.add_edge(edge_key)

    def get_node(self, cwe_id: str) -> Optional[CweNode]:
        """Retrieve a CWE node by its ID."""
        return self.node(cwe_id)

    def get_parents(self, cwe_id: str) -> Set[CweNode]:
        """Retrieve all parent nodes of a given CWE node."""
        node = self.get_node(cwe_id)
        if not node:
            return set()

        return set(self.prev(node))

    def get_children(self, cwe_id: str) -> Set[CweNode]:
        """Retrieve all child nodes of a given CWE node."""
        node = self.get_node(cwe_id)
        if not node:
            return set()

        return set(self.succ(node))

    def get_layer(self, cwe_id: str) -> Dict[str, Any]:
        """Retrieve layer information for a given CWE node."""
        node = self.get_node(cwe_id)
        return node.layer if node else {}

    def get_metadata(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve complete metadata for a CWE node including relationships."""
        node = self.get_node(cwe_id)
        if not node:
            return None

        metadata = node.get_metadata()
        metadata["parents"] = [n.cwe_id for n in self.get_parents(cwe_id)]
        metadata["children"] = [n.cwe_id for n in self.get_children(cwe_id)]
        return metadata

    def get_root_nodes(self) -> List[CweNode]:
        """Retrieve all root nodes in the CWE forest."""
        if self._roots:
            return self._roots
        for node in self.nodes():
            if not any(self.prev(node)):
                self._roots.append(node)
        return self._roots

    def _show_node(
        self, node: CweNode, indent: int = 0, visited: Optional[Set[str]] = None
    ) -> None:
        """Recursively print a CWE node and its children."""
        if visited is None:
            visited = set()

        node_id = node.cwe_id
        if node_id in visited:
            return

        visited.add(node_id)

        prefix = "├── " if indent > 0 else ""
        spaces = "│   " * (indent - 1) if indent > 0 else ""

        print(f"{spaces}{prefix}{node.cwe_id}: {node.name}")

        children = self.get_children(node_id)
        for child in children:
            self._show_node(child, indent + 1, visited)

    def show(self, cwe_id: Optional[str] = None) -> None:
        """Visualize the CWE forest structure starting from a node or all roots."""
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
