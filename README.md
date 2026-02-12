# CWE Tree

Python package for querying the Common Weakness Enumeration (CWE) hierarchy as a multi-rooted forest structure.

## Quick Start

```python
from cwe_tree import query

# Get a node
node = query.get_cwe("CWE-79")  # Both "79" and "CWE-79" works

# Navigate relationships
parents = query.get_parents("CWE-79")
children = query.get_children("CWE-79")

# Get metadata
metadata = query.get_metadata("CWE-79")

# Traverse forest
roots = query.get_root_nodes()
descendants = query.descendants(node)
ancenstors = query.ancenstors(node)

# Subnode Check
query.is_ancestor("CWE-74", "CWE-77")  
query.is_descendant("CWE-77", "CWE-74") 

# Visualize structure
query.show()                    # Display entire forest
query.show("CWE-79")          # Display subtree from specific node
```

## Install

```bash
pip install cwe-tree

# With dev tools (linters, type checker, jupyter)
pip install -e ".[dev]"
# or
uv sync --dev
```

## API

### Core Methods

| Method | Purpose |
|--------|---------|
| `node(cwe_id)` | Get node by ID |
| `nodes(predicate=None)` | Iterate all nodes with optional filter |
| `get_parents(cwe_id)` | Get parent nodes |
| `get_children(cwe_id)` | Get child nodes |
| `get_metadata(cwe_id)` | Get complete node metadata with relationships |
| `get_layer(cwe_id)` | Get layer/depth information |
| `get_root_nodes()` | Get all root nodes (no parents) |
| `show(cwe_id=None)` | Visualize forest structure with ASCII tree |

### Traversal (inherited from AbcGraphQuerier)

| Method | Purpose |
|--------|---------|
| `succ(node, predicate=None)` | Get successor nodes |
| `prev(node, predicate=None)` | Get predecessor nodes |
| `descendants(node, max_depth=None)` | BFS to find all descendants |
| `ancestors(node, max_depth=None)` | BFS to find all ancestors |
| `edges(predicate=None)` | Iterate all edges |
| `first_node(predicate=None)` | Get first matching node |

## Data Model

- **Forest Structure**: Multiple independent trees with different roots (CWEs with no parents)
- **Edge Type**: "PARENT_OF" edges flow parent → child
- **Node Properties**: id, name, abstract (Class/Base/Variant), layer (depth in hierarchies)

## Documentation
- **[docs/demo.ipynb](docs/demo.ipynb)** - Interactive usage examples (Jupyter)
- **[docs/design.md](docs/design.md)** - Architecture, concepts, data contracts
- **[docs/forest.txt](docs/forest.txt)** - Detail structure of CWE Forest


## License

MIT

---
