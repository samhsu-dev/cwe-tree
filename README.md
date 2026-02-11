# CWE Tree

Python package for querying the Common Weakness Enumeration (CWE) hierarchy as a multi-rooted forest structure.

## Quick Start

```python
from cwe_tree import query

# Get a node
node = query.node("CWE-79")  # Normalizes "79" → "CWE-79"

# Navigate relationships
parents = query.get_parents("CWE-79")
children = query.get_children("CWE-79")

# Get metadata
metadata = query.get_metadata("CWE-79")

# Traverse forest
roots = query.get_root_nodes()
descendants = query.descendants(node, max_depth=2)

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
- **Edge Type**: "CHILD" edges flow parent → child
- **Node Properties**: id, name, abstract (Class/Base/Variant), layer (depth in hierarchies)

## Documentation

- **[docs/design.md](docs/design.md)** - Architecture, concepts, data contracts
- **[docs/traversal.md](docs/traversal.md)** - Complete traversal API reference
- **[docs/demo.ipynb](docs/demo.ipynb)** - Interactive usage examples (Jupyter)
- **[SETUP.md](SETUP.md)** - Development setup and workflow
- **[QUALITY.md](QUALITY.md)** - Code quality standards

## Development

### Code Quality

All code must pass (perfect score maintained):

```bash
make quality  # Run all checks

# Or individually:
uv run isort --check-only src/
uv run black --check src/
uv run mypy src/
uv run pylint src/
```

### Format Code

```bash
make format
```

### Run Tests

```bash
# Coming soon - comprehensive test suite
```

## Architecture

See [docs/design.md](docs/design.md) for:
- Problem statement and system role
- Core concepts (nodes, trees, forest structure)
- Project structure
- Data contracts
- Typical scenarios and boundary cases

## License

MIT

## Quality Metrics

| Tool | Score | Notes |
|------|-------|-------|
| pylint | 10.00/10 | Perfect score |
| mypy | ✓ | 0 errors, strict mode |
| black | ✓ | 100-char line length |
| isort | ✓ | PEP 8 compliant |

## Contributing

Ensure all code:
- Has type hints (no `Any` except where necessary)
- Uses Google-style docstrings
- Passes all quality checks (`make quality`)
- Has no redundant interfaces
- Follows [.cursor/rules/codequality.mdc](.cursor/rules/codequality.mdc)

---

For detailed API reference, see [docs/traversal.md](docs/traversal.md).
For interactive examples, see [docs/demo.ipynb](docs/demo.ipynb).
