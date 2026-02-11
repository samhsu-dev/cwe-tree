# CWE Tree Python Package

## Overview

This package provides a structured representation of the [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) hierarchy using a tree-based data model. It allows users to query CWE nodes, understand parent-child relationships, and extract metadata for each CWE entry.

## Features

- **Hierarchical Access**: Easily navigate parent-child relationships in the CWE graph.
- **Rich Metadata**: Access detailed attributes for each CWE ID, including abstraction layers.
- **Pythonic API**: Simple, intuitive query interface.

## Installation

Install using pip:

```sh
pip install cwe-tree
```

## Usage

### Import the package

```python
from cwe_tree import query
```

### Querying CWE nodes

Retrieve a `CweNode` object by its ID:

```python
cwe_node = query.get_cwe("CWE-732")
if cwe_node:
    print(cwe_node.get_metadata())
```

### Fetching parent-child relationships

Traverse the hierarchy:

```python
# Get parent CWEs
parents = query.get_parents("CWE-732")
print("Parent CWE IDs:", parents)

# Get child CWEs
children = query.get_children("CWE-732")
print("Child CWE IDs:", children)
```

### Retrieving metadata

Get a dictionary of metadata for a specific CWE:

```python
metadata = query.get_metadata("CWE-732")
print("CWE Metadata:", metadata)
```

### Getting root nodes

List the top-level nodes in the CWE hierarchy:

```python
roots = query.get_roots()
print("Root CWE nodes:", [node.cwe_id for node in roots])
```

## License

This package is released under the MIT License.
