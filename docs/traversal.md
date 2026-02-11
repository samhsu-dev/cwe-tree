# AbcGraphQuerier Traversal Methods

This document describes the graph traversal methods provided by cpg2py's `AbcGraphQuerier` base class, which `CweForest` inherits and uses for navigating the CWE forest structure.

## Core Traversal Methods

### `succ(node: CweNode, predicate=None) -> Iterable[CweNode]`

Returns all successor nodes connected via outgoing edges from the given node.

**Parameters:**
- `node` - The source CweNode to traverse from
- `predicate` (optional) - Filter function to select successors based on edge conditions

**Returns:** Iterable of successor CweNode instances

**Example:**
```python
from cwe_tree import query

node = query.node("CWE-284")

# Get all successors
all_successors = list(query.succ(node))

# Get successors filtered by edge type
child_successors = list(query.succ(node, lambda e: e.edge_type == "CHILD"))
```

### `prev(node: CweNode, predicate=None) -> Iterable[CweNode]`

Returns all predecessor nodes connected via incoming edges to the given node.

**Parameters:**
- `node` - The target CweNode to traverse from
- `predicate` (optional) - Filter function to select predecessors based on edge conditions

**Returns:** Iterable of predecessor CweNode instances

**Example:**
```python
from cwe_tree import query

node = query.node("CWE-284")

# Get all predecessors
all_predecessors = list(query.prev(node))

# Get predecessors filtered by edge type
parent_predecessors = list(query.prev(node, lambda e: e.edge_type == "CHILD"))
```

## Parent-Child Navigation Methods

### `children(node: CweNode) -> Iterable[CweNode]`

Returns all child nodes connected via `PARENT_OF` edges (or equivalent parent-child relationship edges).

**Parameters:**
- `node` - The parent CweNode

**Returns:** Iterable of child CweNode instances

**Note:** For CWE Forest, this filters successors by `CHILD` edge type.

**Example:**
```python
from cwe_tree import query

node = query.node("CWE-1")
for child in query.children(node):
    print(f"Child: {child.cwe_id} - {child.name}")
```

### `parent(node: CweNode) -> Iterable[CweNode]`

Returns all parent nodes connected via incoming `PARENT_OF` edges (or equivalent).

**Parameters:**
- `node` - The child CweNode

**Returns:** Iterable of parent CweNode instances

**Note:** For CWE Forest, this filters predecessors by `CHILD` edge type.

**Example:**
```python
from cwe_tree import query

node = query.node("CWE-284")
for parent in query.parent(node):
    print(f"Parent: {parent.cwe_id} - {parent.name}")
```

## Graph Traversal Methods

### `descendants(node: CweNode, max_depth=None) -> Iterable[CweNode]`

Performs breadth-first traversal to find all nodes reachable from the source node (all descendants).

**Parameters:**
- `node` - The source CweNode to traverse from
- `max_depth` (optional) - Limit traversal depth

**Returns:** Iterable of all descendant CweNode instances

**Example:**
```python
from cwe_tree import query

root = query.get_root_nodes()[0]

# Get all descendants up to depth 3
descendants = list(query.descendants(root, max_depth=3))
```

### `ancestors(node: CweNode, max_depth=None) -> Iterable[CweNode]`

Performs breadth-first traversal to find all nodes from which the source node is reachable (all ancestors).

**Parameters:**
- `node` - The target CweNode to traverse to
- `max_depth` (optional) - Limit traversal depth

**Returns:** Iterable of all ancestor CweNode instances

**Example:**
```python
from cwe_tree import query

node = query.node("CWE-284")

# Get all ancestors
all_ancestors = list(query.ancestors(node))

# Get ancestors up to depth 5
ancestors_limited = list(query.ancestors(node, max_depth=5))
```

## Node Iteration Methods

### `nodes(predicate=None) -> Iterable[CweNode]`

Iterates over all nodes in the forest, optionally filtered by a predicate function.

**Parameters:**
- `predicate` (optional) - Filter function that returns True for nodes to include

**Returns:** Iterable of all matching CweNode instances

**Example:**
```python
from cwe_tree import query

# Get all nodes
all_nodes = list(query.nodes())

# Get nodes filtered by predicate
class_nodes = list(query.nodes(lambda n: n.abstract == "Class"))

# Count total nodes
total = len(list(query.nodes()))
```

## Edge Iteration Methods

### `edges(predicate=None) -> Iterable[CweEdge]`

Iterates over all edges in the forest, optionally filtered by a predicate function.

**Parameters:**
- `predicate` (optional) - Filter function that returns True for edges to include

**Returns:** Iterable of all matching CweEdge instances

**Example:**
```python
from cwe_tree import query

# Get all edges
all_edges = list(query.edges())

# Get edges of specific type
child_edges = list(query.edges(lambda e: e.edge_type == "CHILD"))
```

## Utility Methods

### `first_node(predicate=None) -> Optional[CweNode]`

Returns the first node matching the predicate, or None if no match found.

**Parameters:**
- `predicate` (optional) - Filter function

**Returns:** A single CweNode instance or None

**Example:**
```python
from cwe_tree import query

# Find first class-type node
first_class = query.first_node(lambda n: n.abstract == "Class")
```

## CWE Forest Integration

The CweForest class extends these AbcGraphQuerier methods with CWE-specific wrappers:

| AbcGraphQuerier Method | CweForest Wrapper | Purpose |
|---|---|---|
| `succ(node)` | `get_children(cwe_id)` | Get child weaknesses (type-safe, ID-normalized) |
| `prev(node)` | `get_parents(cwe_id)` | Get parent weaknesses (type-safe, ID-normalized) |
| `children(node)` | Used internally | - |
| `parent(node)` | Used internally | - |
| `nodes()` | Used in `get_root_nodes()` | Filter root nodes (no parents) |

## Edge Type Reference

The CWE Forest uses a single edge type for all relationships:

- **`CHILD`** - Represents parent-child relationships (parent → child direction)
  - Traversed forward with `succ()` or `children()` from parent
  - Traversed backward with `prev()` or `parent()` from child

## Performance Considerations

- **Traversal methods:** Return iterables (lazy evaluation) rather than lists
- **Breadth-first traversal:** `descendants()` and `ancestors()` explore level-by-level
- **Predicate filtering:** Applied during traversal for early termination
- **Max depth limiting:** Prevents deep traversals on large forests

## Best Practices

1. **Use CweForest wrappers** - Prefer `get_children()`, `get_parents()` for consistent semantics
2. **Leverage predicates** - Filter during traversal rather than post-processing
3. **Limit traversal depth** - Use `max_depth` parameter on large forests
4. **Convert to list cautiously** - Iterables are memory-efficient; only convert when needed
