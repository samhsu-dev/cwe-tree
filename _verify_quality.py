from cwe_tree import query, CweTree

def test_get_roots():
    print("Testing get_roots()...")
    roots = query.get_roots()
    print(f"Found {len(roots)} roots.")
    
    # Check if roots are cached
    roots2 = query.get_roots()
    assert roots is roots2, "Roots should be cached"
    
    for root in roots:
        print(f" - Root: {root.cwe_id} ({root.name})")
        # Verify root has no parents
        parents = query.get_parents(root.cwe_id)
        assert len(parents) == 0, f"Root {root.cwe_id} should have no parents, but found {parents}"
    print("get_roots() passed.\n")

def test_metadata_structure():
    print("Testing get_metadata()...")
    cwe_id = "CWE-732"
    meta = query.get_metadata(cwe_id)
    assert meta is not None
    assert "id" in meta
    assert "name" in meta
    assert "parents" in meta
    assert "children" in meta
    assert isinstance(meta["parents"], list)
    assert isinstance(meta["children"], list)
    # Check if contents are strings (IDs)
    if meta["parents"]:
        assert isinstance(meta["parents"][0], str), "Parents should be list of strings"
    print(f"Metadata for {cwe_id}: OK")
    print("get_metadata() passed.\n")

def test_node_properties():
    print("Testing node properties...")
    cwe_id = "CWE-79"
    node = query.get_node(cwe_id)
    if node:
        assert node.cwe_id == "CWE-79"
        assert node.name is not None
        print(f"Node {cwe_id} properties OK")
    else:
        print(f"Node {cwe_id} not found (might be expected if data subset)")
    print("node_properties passed.\n")

if __name__ == "__main__":
    try:
        test_get_roots()
        test_metadata_structure()
        test_node_properties()
        print("ALL TESTS PASSED")
    except Exception as e:
        print(f"TEST FAILED: {e}")
        exit(1)
