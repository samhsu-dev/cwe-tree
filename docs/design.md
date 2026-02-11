# Design: CWE Tree

## 1. Context

**Problem Statement**
Security researchers and developers struggle to programmatically navigate the Common Weakness Enumeration (CWE) hierarchy due to its complex, graph-like structure. Existing static lists lack the relational context needed for automated vulnerability analysis and tool integration.

**System Role**
The `cwe_tree` module serves as the foundational data layer for accessing, traversing, and querying CWE definitions and their hierarchical relationships.

**Data Flow**
- **Inputs:** `nodes.csv` (definitions), `rels.csv` (relationships)
- **Outputs:** `CweNode` objects, `CweTree` structure, metadata dictionaries
- **Connections:** [Raw CSV Data] → [cwe_tree] → [Security Analysis Tools / User Scripts]

**Scope Boundaries**
- **Owned:** Parsing CSV representations, building in-memory tree structures, providing traversal and query APIs.
- **Not Owned:** Triage logic, vulnerability scanning, static analysis, or modifying official CWE definitions.

## 2. Concepts

**Conceptual Diagram**
```
[CweTree]
    │
    ├── manages ──> [CweNode (ID: CWE-79)]
    │                   │
    │                   ├── parents ──> {CweNode (ID: CWE-74)}
    │                   └── children ──> {CweNode (ID: CWE-80), ...}
    │
    └── lookup ───> { "CWE-79": <CweNode Object>, ... }
```

**Core Concepts**

**CWE Node**
- **Definition:** An object representing a specific weakness type identified by a unique ID (e.g., CWE-79).
- **Scope:** Encapsulates intrinsic properties like name, abstraction level, and layer depth within various root trees.
- **Relationships:** Linked bi-directionally to parent and child nodes within the `CweTree`.

**CWE Tree**
- **Definition:** The holistic container class that represents the entire graph of known weaknesses.
- **Scope:** Manages the lifecycle, storage, and retrieval of all `CweNode` instances.
- **Relationships:** Composed of a collection of `CweNode` objects; acts as the entry point for all queries.

**Abstraction Layer**
- **Definition:** A categorization attribute indicating the specificity of a weakness (e.g., Class, Base, Variant).
- **Scope:** A property of a `CweNode` that aids in filtering and understanding the granularity of a weakness.
- **Relationships:** Used to organize nodes within the hierarchy but does not strictly dictate parent-child structure.

## 3. Project Structure

The project is structured as a standard Python package:

- **`src/cwe_tree/`**: The core package.
    - **`_node.py`**: Defines the `CweNode` class.
    - **`_tree.py`**: Defines the `CweTree` class and data loading logic.
    - **`query.py`**: Provides a high-level query interface (singleton access).
    - **`resources/`**: Contains the `nodes.csv` and `rels.csv` data files.
- **`scripts/`**: Helper scripts for development (e.g., `release.py`).

## 4. Contracts & Flow

**Data Contracts**
- **With Consumer:** APIs return `CweNode` objects or metadata dictionaries containing standardized keys: `id`, `name`, `abstract`, `layer`, `parents`, `children`.

**Internal Processing Flow**
1. **Initialization:** Module import triggers the creation of a singleton `CweTree` instance.
2. **Data Loading:** The `_load_data` function reads `nodes.csv` and populates the tree with `CweNode` objects.
3. **Relationship Linking:** The function then reads `rels.csv` to establish parent-child edges between existing nodes.
4. **Access:** Users query the populated tree via public methods like `get_node` or `get_children`.

## 5. Scenarios

**Typical**
A user queries for "CWE-79" to retrieve its metadata. The system returns a `CweNode` object, from which the user extracts the list of child nodes to identify specific XSS variants for targeted scanning.

**Boundary**
A user queries for a non-existent ID (e.g., "CWE-99999"). The system gracefully returns `None`, allowing the consuming script to handle the missing data without crashing.

**Interaction**
A static analysis tool integration uses `cwe_tree` to fetch the ancestry of a flagged vulnerability. It traverses up the `parents` references to find the high-level "Class" or "Pillar" weakness for reporting purposes.
