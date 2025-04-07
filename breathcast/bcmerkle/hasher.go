package bcmerkle

// Hasher is the user-defined interface for hashing leaves and nodes.
// The [Tree] passes the raw leaf data to the Leaf method to create a leaf node,
// and it passes raw data from Leaf calls to the Node method.
//
// To be allocation-efficient, the Hasher implementation
// must append its hash output to dst, instead of creating a new byte slice.
// Hasher must not retain references to the dst slice.
//
// Furthermore, Hasher methods must be safe to call concurrently.
type Hasher interface {
	Leaf(in []byte, c LeafContext, dst []byte)
	Node(left, right []byte, c NodeContext, dst []byte)
}

// LeafContext is additional context for [Hasher.Leaf].
type LeafContext struct {
	// Optional fixed nonce for every leaf or node.
	// The nonce may be nil if the driver chooses to omit it.
	Nonce []byte

	// The index of the leaf within the entire tree.
	// Encoded as a big-endian uint16.
	LeafIndex [2]byte
}

// NodeContext is additional context for [Hasher.Node].
type NodeContext struct {
	// Optional fixed nonce for every leaf or node.
	// The nonce may be nil if the driver chooses to omit it.
	Nonce []byte

	// The range of leaf indices this node covers, inclusive.
	// Each is encoded as a big-endian uint16.
	FirstLeafIndex, LastLeafIndex [2]byte
}
