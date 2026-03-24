"""Tests for Merkle Tree audit integrity."""

import pytest
import json
from aib.merkle import (
    MerkleTree, MerkleProof, MerkleAnchor, AnchorChain,
    sha256, hash_pair,
)


# ═══════════════════════════════════════════════════════════════════
# Hash primitives
# ═══════════════════════════════════════════════════════════════════

class TestHashPrimitives:

    def test_sha256_deterministic(self):
        assert sha256("hello") == sha256("hello")

    def test_sha256_different_input(self):
        assert sha256("hello") != sha256("world")

    def test_sha256_length(self):
        assert len(sha256("test")) == 64

    def test_hash_pair(self):
        h = hash_pair("aaa", "bbb")
        assert len(h) == 64
        assert h == sha256("aaa" + "bbb")

    def test_hash_pair_order_matters(self):
        assert hash_pair("a", "b") != hash_pair("b", "a")


# ═══════════════════════════════════════════════════════════════════
# Tree construction
# ═══════════════════════════════════════════════════════════════════

class TestTreeConstruction:

    def test_empty_tree(self):
        tree = MerkleTree()
        assert tree.size == 0
        assert tree.root == MerkleTree.EMPTY_HASH

    def test_single_leaf(self):
        tree = MerkleTree(["leaf1"])
        assert tree.size == 1
        assert tree.root == "leaf1"

    def test_two_leaves(self):
        tree = MerkleTree(["a", "b"])
        assert tree.size == 2
        assert tree.root == hash_pair("a", "b")

    def test_three_leaves(self):
        tree = MerkleTree(["a", "b", "c"])
        assert tree.size == 3
        # c is duplicated: hash(hash(a,b), hash(c,c))
        expected = hash_pair(hash_pair("a", "b"), hash_pair("c", "c"))
        assert tree.root == expected

    def test_four_leaves(self):
        tree = MerkleTree(["a", "b", "c", "d"])
        assert tree.size == 4
        expected = hash_pair(hash_pair("a", "b"), hash_pair("c", "d"))
        assert tree.root == expected

    def test_power_of_two(self):
        leaves = [sha256(str(i)) for i in range(8)]
        tree = MerkleTree(leaves)
        assert tree.size == 8
        assert tree.depth == 4  # 3 layers + 1

    def test_incremental_add(self):
        tree1 = MerkleTree(["a", "b", "c"])

        tree2 = MerkleTree()
        tree2.add("a")
        tree2.add("b")
        tree2.add("c")

        assert tree1.root == tree2.root

    def test_add_many(self):
        tree = MerkleTree()
        tree.add_many(["a", "b", "c", "d"])
        expected = MerkleTree(["a", "b", "c", "d"])
        assert tree.root == expected.root

    def test_depth(self):
        assert MerkleTree([]).depth == 0
        assert MerkleTree(["a"]).depth == 1
        assert MerkleTree(["a", "b"]).depth == 2
        assert MerkleTree(["a", "b", "c", "d"]).depth == 3

    def test_repr(self):
        tree = MerkleTree(["a", "b", "c"])
        r = repr(tree)
        assert "leaves=3" in r


# ═══════════════════════════════════════════════════════════════════
# Merkle Proofs
# ═══════════════════════════════════════════════════════════════════

class TestMerkleProofs:

    def test_proof_single_leaf(self):
        tree = MerkleTree(["only"])
        proof = tree.get_proof(0)
        assert proof.verify() is True

    def test_proof_two_leaves(self):
        tree = MerkleTree(["a", "b"])
        p0 = tree.get_proof(0)
        p1 = tree.get_proof(1)
        assert p0.verify() is True
        assert p1.verify() is True

    def test_proof_four_leaves(self):
        tree = MerkleTree(["a", "b", "c", "d"])
        for i in range(4):
            proof = tree.get_proof(i)
            assert proof.verify() is True, f"Proof failed for leaf {i}"

    def test_proof_large_tree(self):
        leaves = [sha256(str(i)) for i in range(100)]
        tree = MerkleTree(leaves)
        # Verify random leaves
        for i in [0, 1, 42, 73, 99]:
            proof = tree.get_proof(i)
            assert proof.verify() is True, f"Proof failed for leaf {i}"

    def test_proof_odd_number_of_leaves(self):
        tree = MerkleTree(["a", "b", "c", "d", "e"])
        for i in range(5):
            proof = tree.get_proof(i)
            assert proof.verify() is True

    def test_proof_has_log_n_steps(self):
        leaves = [sha256(str(i)) for i in range(1024)]
        tree = MerkleTree(leaves)
        proof = tree.get_proof(500)
        # log2(1024) = 10
        assert len(proof.steps) == 10

    def test_proof_index_out_of_range(self):
        tree = MerkleTree(["a", "b"])
        with pytest.raises(IndexError):
            tree.get_proof(5)

    def test_proof_negative_index(self):
        tree = MerkleTree(["a", "b"])
        with pytest.raises(IndexError):
            tree.get_proof(-1)

    def test_static_verify(self):
        tree = MerkleTree(["a", "b", "c", "d"])
        proof = tree.get_proof(2)
        # Verify without having the tree
        assert MerkleTree.verify_proof(proof) is True

    def test_proof_serialization(self):
        tree = MerkleTree(["a", "b", "c", "d"])
        proof = tree.get_proof(1)
        d = proof.to_dict()
        restored = MerkleProof.from_dict(d)
        assert restored.verify() is True
        assert restored.leaf_index == 1

    def test_proof_json_roundtrip(self):
        tree = MerkleTree([sha256(str(i)) for i in range(16)])
        proof = tree.get_proof(7)
        json_str = json.dumps(proof.to_dict())
        restored = MerkleProof.from_dict(json.loads(json_str))
        assert restored.verify() is True


# ═══════════════════════════════════════════════════════════════════
# Tamper detection
# ═══════════════════════════════════════════════════════════════════

class TestTamperDetection:

    def test_tampered_leaf_fails_proof(self):
        tree = MerkleTree(["a", "b", "c", "d"])
        proof = tree.get_proof(2)

        # Tamper with the leaf hash in the proof
        proof.leaf_hash = sha256("tampered")
        assert proof.verify() is False

    def test_tampered_sibling_fails_proof(self):
        tree = MerkleTree(["a", "b", "c", "d"])
        proof = tree.get_proof(0)

        # Tamper with a sibling hash
        if proof.steps:
            h, d = proof.steps[0]
            proof.steps[0] = (sha256("fake"), d)
        assert proof.verify() is False

    def test_tampered_root_fails_proof(self):
        tree = MerkleTree(["a", "b", "c", "d"])
        proof = tree.get_proof(1)

        # Tamper with the root
        proof.root_hash = sha256("fake-root")
        assert proof.verify() is False

    def test_verify_tree_detects_corruption(self):
        tree = MerkleTree(["a", "b", "c", "d"])
        valid, msg = tree.verify_tree()
        assert valid is True

        # Corrupt a leaf
        tree._leaves[2] = "corrupted"
        tree._dirty = False  # Prevent rebuild

        valid, msg = tree.verify_tree()
        assert valid is False
        assert "mismatch" in msg.lower()

    def test_verify_tree_valid(self):
        leaves = [sha256(str(i)) for i in range(50)]
        tree = MerkleTree(leaves)
        valid, msg = tree.verify_tree()
        assert valid is True
        assert "50 leaves" in msg


# ═══════════════════════════════════════════════════════════════════
# Layers
# ═══════════════════════════════════════════════════════════════════

class TestLayers:

    def test_get_leaf_layer(self):
        tree = MerkleTree(["a", "b", "c", "d"])
        leaves = tree.get_layer(0)
        assert leaves == ["a", "b", "c", "d"]

    def test_get_root_layer(self):
        tree = MerkleTree(["a", "b", "c", "d"])
        root_layer = tree.get_layer(-1)
        assert len(root_layer) == 1
        assert root_layer[0] == tree.root

    def test_get_middle_layer(self):
        tree = MerkleTree(["a", "b", "c", "d"])
        mid = tree.get_layer(1)
        assert len(mid) == 2
        assert mid[0] == hash_pair("a", "b")
        assert mid[1] == hash_pair("c", "d")

    def test_get_invalid_layer(self):
        tree = MerkleTree(["a", "b"])
        assert tree.get_layer(99) == []


# ═══════════════════════════════════════════════════════════════════
# Anchor Chain
# ═══════════════════════════════════════════════════════════════════

class TestAnchorChain:

    def test_create_anchor(self):
        tree = MerkleTree(["a", "b", "c"])
        chain = AnchorChain()
        anchor = chain.create_anchor(tree)

        assert anchor.root_hash == tree.root
        assert anchor.tree_size == 3
        assert anchor.anchor_id.startswith("anchor_")
        assert anchor.previous_anchor_hash is None  # First anchor

    def test_chain_links_anchors(self):
        chain = AnchorChain()

        tree1 = MerkleTree(["a", "b"])
        a1 = chain.create_anchor(tree1)

        tree2 = MerkleTree(["a", "b", "c"])
        a2 = chain.create_anchor(tree2)

        assert a1.previous_anchor_hash is None
        assert a2.previous_anchor_hash is not None

    def test_verify_anchor_chain(self):
        chain = AnchorChain()
        for i in range(5):
            tree = MerkleTree([sha256(str(j)) for j in range(i + 1)])
            chain.create_anchor(tree)

        valid, count, msg = chain.verify_chain()
        assert valid is True
        assert count == 5

    def test_detect_tampered_anchor(self):
        chain = AnchorChain()
        tree = MerkleTree(["a"])
        chain.create_anchor(tree)
        chain.create_anchor(tree)
        chain.create_anchor(tree)

        # Tamper
        chain._anchors[1].root_hash = "tampered"

        valid, idx, msg = chain.verify_chain()
        assert valid is False
        assert idx == 2

    def test_latest_anchor(self):
        chain = AnchorChain()
        assert chain.latest is None

        tree = MerkleTree(["a"])
        chain.create_anchor(tree)
        assert chain.latest is not None
        assert chain.latest.tree_size == 1

    def test_export_anchors(self):
        chain = AnchorChain()
        tree = MerkleTree(["a", "b"])
        chain.create_anchor(tree, metadata={"note": "hourly"})
        exported = chain.export()
        assert len(exported) == 1
        assert exported[0]["metadata"]["note"] == "hourly"

    def test_anchor_count(self):
        chain = AnchorChain()
        tree = MerkleTree(["x"])
        for _ in range(3):
            chain.create_anchor(tree)
        assert chain.count == 3
