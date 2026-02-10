from cwe_tree import query

cwe_id = "CWE-732"
# cwe_node = query.get_node(cwe_id) # Node object still exists but is lightweight
# print(f"Metadata of {cwe_id}: {cwe_node.get_metadata()}") # This would now return only intrinsic props

# Use query.get_metadata for full info including relations
print(f"Metadata of {cwe_id}: {query.get_metadata(cwe_id)}")
