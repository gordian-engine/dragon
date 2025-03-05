// Package cbmt contains an internal implementation
// of a "compact binary Merkle tree".
//
// The tree is binary: each non-leaf node has exactly two children.
// It is compact: hashes are stored in one contiguous memory allocation,
// and leaf counts that are not a power of two are handled by
// pairing the "overflow" leaves to keep the rest of the tree
// a perfect binary tree, all at the same depth.
// This means, the last leaf elements that overflow past the power of two
// will have one more depth than the other elements.
// Assuming typical arrangement of erasure-coded data,
// it will be parity chunks, or possibly some of the final data chunks,
// that require one more proof element.
package cbmt
