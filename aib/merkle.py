"""
AIB — Merkle Tree for Audit Integrity.

Replaces O(N) chain verification with O(log N) Merkle Proofs.

Why this matters:
- Linear hash chain: verify receipt #87,432 → traverse 87,431 hashes
- Merkle tree: verify receipt #87,432 → check 17 hashes (log2 of 100,000)

How it works:
1. Each Action Receipt hash is a LEAF in the tree
2. Each internal NODE = SHA-256(left_child + right_child)
3. The ROOT hash summarizes the entire audit history
4. A PROOF for any leaf = the sibling hashes along the path to the root
5. Anyone with the root hash can verify any single receipt in O(log N)

Use cases:
- Auditor verifies a specific receipt without downloading the entire history
- Published Merkle Root (e.g. on a public ledger) anchors the entire audit
- Selective disclosure: prove a receipt exists without revealing other receipts
- Efficient sync: two AIB instances compare roots to detect divergence

Future (v2): Zero-Knowledge Proofs on top of the Merkle Tree for
proving properties ("an agent in org X performed action Y") without
revealing which agent or the exact action details.
"""

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Optional


def sha256(data: str) -> str:
    """SHA-256 hash of a string, returns hex digest."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def hash_pair(left: str, right: str) -> str:
    """Hash two child nodes together to form a parent node."""
    return sha256(left + right)


# ── Merkle Proof ──────────────────────────────────────────────────

@dataclass
class MerkleProof:
    """
    Proof that a specific leaf exists in the tree.

    Contains the sibling hashes along the path from the leaf to the root.
    Each step is (hash, direction) where direction is "left" or "right"
    indicating which side the sibling is on.
    """
    leaf_hash: str
    leaf_index: int
    steps: list[tuple[str, str]]   # [(sibling_hash, "left"|"right"), ...]
    root_hash: str
    tree_size: int

    def verify(self) -> bool:
        """
        Verify this proof against the root hash.

        Recomputes the path from the leaf to the root using the
        sibling hashes and checks if the result matches the root.
        """
        current = self.leaf_hash
        for sibling_hash, direction in self.steps:
            if direction == "left":
                current = hash_pair(sibling_hash, current)
            else:
                current = hash_pair(current, sibling_hash)
        return current == self.root_hash

    def to_dict(self) -> dict:
        return {
            "leaf_hash": self.leaf_hash,
            "leaf_index": self.leaf_index,
            "steps": [{"hash": h, "direction": d} for h, d in self.steps],
            "root_hash": self.root_hash,
            "tree_size": self.tree_size,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MerkleProof":
        return cls(
            leaf_hash=d["leaf_hash"],
            leaf_index=d["leaf_index"],
            steps=[(s["hash"], s["direction"]) for s in d["steps"]],
            root_hash=d["root_hash"],
            tree_size=d["tree_size"],
        )


# ── Merkle Tree ───────────────────────────────────────────────────

class MerkleTree:
    """
    Merkle Tree for Action Receipt integrity proofs.

    Builds a binary hash tree from receipt hashes.
    Supports incremental building (add receipts one by one)
    and efficient proof generation.

    Usage:
        tree = MerkleTree()

        # Add receipt hashes (from ReceiptStore)
        tree.add(receipt1.receipt_hash)
        tree.add(receipt2.receipt_hash)
        tree.add(receipt3.receipt_hash)

        # Get the root (summarizes everything)
        print(tree.root)  # "a3f2...c1d8"

        # Generate a proof for receipt #1
        proof = tree.get_proof(1)
        assert proof.verify()  # True

        # Anyone with just the root can verify
        assert MerkleTree.verify_proof(proof)  # True
    """

    EMPTY_HASH = sha256("aib:merkle:empty")

    def __init__(self, leaves: Optional[list[str]] = None):
        self._leaves: list[str] = []
        self._layers: list[list[str]] = []
        self._dirty: bool = True

        if leaves:
            for leaf in leaves:
                self._leaves.append(leaf)
            self._build()

    def add(self, leaf_hash: str):
        """Add a leaf (receipt hash) to the tree."""
        self._leaves.append(leaf_hash)
        self._dirty = True

    def add_many(self, leaf_hashes: list[str]):
        """Add multiple leaves at once."""
        self._leaves.extend(leaf_hashes)
        self._dirty = True

    @property
    def root(self) -> str:
        """The Merkle Root — a single hash summarizing all receipts."""
        if self._dirty:
            self._build()
        if not self._layers:
            return self.EMPTY_HASH
        return self._layers[-1][0]

    @property
    def size(self) -> int:
        """Number of leaves in the tree."""
        return len(self._leaves)

    @property
    def depth(self) -> int:
        """Depth of the tree (number of layers above leaves)."""
        if not self._leaves:
            return 0
        return math.ceil(math.log2(max(len(self._leaves), 1))) + 1

    def get_proof(self, index: int) -> MerkleProof:
        """
        Generate a Merkle Proof for the leaf at the given index.

        The proof contains O(log N) hashes — the siblings along the
        path from the leaf to the root.
        """
        if self._dirty:
            self._build()

        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"Leaf index {index} out of range (0..{len(self._leaves)-1})")

        steps = []
        idx = index

        for layer in self._layers[:-1]:  # All layers except root
            # Determine sibling
            if idx % 2 == 0:
                # Current is left child, sibling is right
                sibling_idx = idx + 1
                if sibling_idx < len(layer):
                    steps.append((layer[sibling_idx], "right"))
                else:
                    # No sibling (odd number of nodes), duplicate self
                    steps.append((layer[idx], "right"))
            else:
                # Current is right child, sibling is left
                sibling_idx = idx - 1
                steps.append((layer[sibling_idx], "left"))

            idx = idx // 2

        return MerkleProof(
            leaf_hash=self._leaves[index],
            leaf_index=index,
            steps=steps,
            root_hash=self.root,
            tree_size=len(self._leaves),
        )

    @staticmethod
    def verify_proof(proof: MerkleProof) -> bool:
        """
        Verify a Merkle Proof WITHOUT having the full tree.

        Only needs the proof object (which contains the root hash).
        This is what an auditor uses.
        """
        return proof.verify()

    def verify_tree(self) -> tuple[bool, str]:
        """
        Verify the internal consistency of the entire tree.

        Recomputes all layers from the leaves and checks
        that the computed root matches the stored root.
        """
        if not self._leaves:
            return True, "Empty tree"

        # Recompute from scratch
        layer = list(self._leaves)
        while len(layer) > 1:
            next_layer = []
            for i in range(0, len(layer), 2):
                left = layer[i]
                right = layer[i + 1] if i + 1 < len(layer) else layer[i]
                next_layer.append(hash_pair(left, right))
            layer = next_layer

        computed_root = layer[0]
        if computed_root == self.root:
            return True, f"Tree valid ({self.size} leaves, depth {self.depth})"
        else:
            return False, f"Root mismatch: stored={self.root[:16]}..., computed={computed_root[:16]}..."

    def get_layer(self, level: int) -> list[str]:
        """Get all hashes at a specific layer (0 = leaves, -1 = root)."""
        if self._dirty:
            self._build()
        if level < 0:
            level = len(self._layers) + level
        if level < 0 or level >= len(self._layers):
            return []
        return list(self._layers[level])

    # ── Internal ──────────────────────────────────────────────

    def _build(self):
        """Build/rebuild the tree from leaves."""
        self._layers = []
        if not self._leaves:
            self._dirty = False
            return

        # Layer 0: leaves
        layer = list(self._leaves)
        self._layers.append(layer)

        # Build up
        while len(layer) > 1:
            next_layer = []
            for i in range(0, len(layer), 2):
                left = layer[i]
                right = layer[i + 1] if i + 1 < len(layer) else layer[i]
                next_layer.append(hash_pair(left, right))
            layer = next_layer
            self._layers.append(layer)

        self._dirty = False

    def __repr__(self):
        return f"MerkleTree(leaves={self.size}, depth={self.depth}, root={self.root[:16]}...)"


# ── Anchoring ─────────────────────────────────────────────────────

@dataclass
class MerkleAnchor:
    """
    A timestamped Merkle Root that anchors the audit state.

    Publish this periodically (e.g. hourly) to a public ledger,
    blockchain, or simply your company blog. Anyone who saved
    the anchor can later verify that the audit trail hasn't been
    tampered with since that point.
    """
    root_hash: str
    tree_size: int
    timestamp: str
    anchor_id: str
    previous_anchor_hash: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "anchor_id": self.anchor_id,
            "root_hash": self.root_hash,
            "tree_size": self.tree_size,
            "timestamp": self.timestamp,
            "previous_anchor_hash": self.previous_anchor_hash,
            "metadata": self.metadata,
        }


class AnchorChain:
    """
    Chain of Merkle Root anchors over time.

    Each anchor captures the Merkle Root at a point in time.
    The chain of anchors is itself hash-linked.
    Publish these to make your audit trail publicly verifiable.
    """

    def __init__(self):
        self._anchors: list[MerkleAnchor] = []

    def create_anchor(
        self,
        tree: MerkleTree,
        metadata: Optional[dict] = None,
    ) -> MerkleAnchor:
        """Create a new anchor from the current tree state."""
        from datetime import datetime, timezone
        import uuid

        prev_hash = None
        if self._anchors:
            prev = self._anchors[-1]
            prev_hash = sha256(json.dumps(prev.to_dict(), sort_keys=True))

        anchor = MerkleAnchor(
            root_hash=tree.root,
            tree_size=tree.size,
            timestamp=datetime.now(timezone.utc).isoformat(),
            anchor_id=f"anchor_{uuid.uuid4().hex[:12]}",
            previous_anchor_hash=prev_hash,
            metadata=metadata or {},
        )
        self._anchors.append(anchor)
        return anchor

    def verify_chain(self) -> tuple[bool, int, str]:
        """Verify the anchor chain integrity."""
        if not self._anchors:
            return True, 0, "Empty chain"

        for i in range(1, len(self._anchors)):
            prev = self._anchors[i - 1]
            curr = self._anchors[i]
            expected = sha256(json.dumps(prev.to_dict(), sort_keys=True))
            if curr.previous_anchor_hash != expected:
                return False, i, f"Anchor chain broken at #{i}"

        return True, len(self._anchors), "Chain valid"

    @property
    def latest(self) -> Optional[MerkleAnchor]:
        return self._anchors[-1] if self._anchors else None

    @property
    def count(self) -> int:
        return len(self._anchors)

    def export(self) -> list[dict]:
        return [a.to_dict() for a in self._anchors]
