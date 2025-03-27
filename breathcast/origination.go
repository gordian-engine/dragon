package breathcast

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/gordian-engine/dragon/breathcast/bcmerkle"
	"github.com/gordian-engine/dragon/breathcast/internal/merkle/cbmt"
	"github.com/klauspost/reedsolomon"
)

// PrepareOriginationConfig is the config for [PrepareOrigination].
type PrepareOriginationConfig struct {
	// Desired maximum size of error-corrected chunk data.
	// This is exclusively the chunk data,
	// without any other headers or metadata.
	// There may be internal restrictions on the chunk size
	// that result in a size slightly smaller than the given value.
	MaxChunkSize int

	// The protocol ID byte.
	// Required for creating data for outgoing datagrams.
	ProtocolID byte

	// A unique header to identify this operation.
	// This contributes to the chunk size.
	// This header will be used by all participants in this broadcast,
	// so the application must take care to ensure its uniqueness.
	OperationHeader []byte

	// ParityRatio indicates the desired ratio of
	// parity chunks to data chunks.
	// For example, ParityRatio=0.25 means there will be
	// one parity chunk for every four data chunks.
	// The parity count is rounded down
	// if the ratio does not result in a whole number.
	ParityRatio float32

	// How many tiers of the Merkle tree will be included in the header.
	// Zero means only the root will be included;
	// one means the root and its immediate children will be included;
	// two means the root, its immediate children,
	// and its grandchildren will be included; and so on.
	//
	// Including more tiers in the header means the header size grows,
	// but it also means the built fragments
	// require fewer bytes dedicated to Merkle proofs.
	HeaderProofTier uint8

	// How to hash entries in the underlying Merkle tree.
	Hasher bcmerkle.Hasher

	// The size, in bytes, of hashes used in the Merkle tree.
	// This is necessary for preparing the Merkle tree,
	// and it also contributes to the chunk size.
	HashSize int

	// An unpredictable value to be included in hashes in the Merkle tree.
	// The value must be sent as part of the origination header,
	// so that clients can verify Merkle proofs.
	Nonce []byte
}

// PreparedOrigination is the value returned by [PrepareOrigination].
type PreparedOrigination struct {
	// The number of data and parity chunks.
	NumData, NumParity int

	// RootProof is the set of proofs
	// to be included in the origination header.
	// A longer root proof in the header
	// allows the chunk proofs to be shorter.
	RootProof [][]byte

	// The data and parity chunks, with metadata included.
	// These are ready to be transfered over the network.
	// TODO: this could be unexported because it is internal to this package.
	Chunks [][]byte
}

// PrepareOrigination converts the given data and config
// into a PreparedOrigination.
//
// The application can then transform the PreparedOrigination
// into a full origination to be passed to [*Protocol.Originate].
func PrepareOrigination(
	data []byte,
	cfg PrepareOriginationConfig,
) (PreparedOrigination, error) {
	if cfg.ParityRatio < 0 {
		panic(fmt.Errorf(
			"BUG: ParityRatio must be non-negative (got %g)", cfg.ParityRatio,
		))
	}
	if cfg.HashSize <= 0 {
		panic(fmt.Errorf(
			"BUG: MerkleHashSize must be positive (got %d)", cfg.HashSize,
		))
	}

	estimatedDataChunks := len(data) / cfg.MaxChunkSize
	if len(data)%cfg.MaxChunkSize > 0 {
		estimatedDataChunks++
	}

	estimatedParityChunks := int(cfg.ParityRatio * float32(estimatedDataChunks))
	estimatedTotalChunks := estimatedDataChunks + estimatedParityChunks

	treeDepth := bits.Len(uint(estimatedTotalChunks))
	proofNodesPerChunk := max(0, treeDepth-int(cfg.HeaderProofTier))
	merkleProofSize := proofNodesPerChunk * cfg.HashSize

	// Each of these have a 1-byte length header.
	merkleOverhead := 1 + merkleProofSize
	operationHeaderOverhead := 1 + len(cfg.OperationHeader)

	const protocolOverhead = 15 // TODO: calculate this

	totalOverhead := merkleOverhead + operationHeaderOverhead + protocolOverhead

	effectiveMaxChunkSize := cfg.MaxChunkSize - totalOverhead

	const minChunkSize = 32
	if effectiveMaxChunkSize < minChunkSize {
		return PreparedOrigination{}, fmt.Errorf(
			"chunk size too small: minimum is %d but calculated %d",
			minChunkSize, effectiveMaxChunkSize,
		)
	}

	expShardCount := (len(data) / effectiveMaxChunkSize) +
		int(cfg.ParityRatio*float32(len(data))/float32(effectiveMaxChunkSize))

	if expShardCount > 255 {
		// Round down to nearest multiple of 64.
		effectiveMaxChunkSize -= (effectiveMaxChunkSize % 64)

		if effectiveMaxChunkSize < minChunkSize {
			return PreparedOrigination{}, fmt.Errorf(
				"chunk size too small after aligning for %d shards: minimum is %d but calculated %d",
				expShardCount, minChunkSize, effectiveMaxChunkSize,
			)
		}
	}

	nData := len(data) / effectiveMaxChunkSize
	if len(data)%effectiveMaxChunkSize > 0 {
		nData++
	}

	nParity := int(cfg.ParityRatio * float32(nData))
	totalChunks := nData + nParity

	if totalChunks > (1<<16)-1 {
		return PreparedOrigination{}, fmt.Errorf(
			"data too large: resulted in %d data and %d parity chunks, but limit is %d",
			nData, nParity, (1<<16)-1,
		)
	}

	enc, err := reedsolomon.New(
		nData, nParity,
		reedsolomon.WithAutoGoroutines(effectiveMaxChunkSize),
	)
	if err != nil {
		return PreparedOrigination{}, fmt.Errorf(
			"failed to build Reed-Solomon encoder: %w", err,
		)
	}

	po := PreparedOrigination{
		NumData:   nData,
		NumParity: nParity,
	}

	rawChunks, err := enc.Split(data)
	if err != nil {
		return po, fmt.Errorf(
			"failed to split data for chunking: %w", err,
		)
	}

	if err := enc.Encode(rawChunks); err != nil {
		return po, fmt.Errorf(
			"failed to erasure-code data: %w", err,
		)
	}

	// Now that the data is erasure-coded,
	// we can build the Merkle tree.

	t := cbmt.NewEmptyTree(uint16(nData+nParity), cfg.HashSize)

	res := t.Populate(rawChunks, cbmt.PopulateConfig{
		Hasher: cfg.Hasher,
		Nonce:  cfg.Nonce,

		ProofCutoffTier: cfg.HeaderProofTier,
	})

	po.RootProof = res.RootProof
	po.Chunks = buildDatagrams(rawChunks, res.Proofs, cfg)

	return po, nil
}

func buildDatagrams(rawChunks [][]byte, chunkProofs [][][]byte, cfg PrepareOriginationConfig) [][]byte {
	n := uint16(len(rawChunks))
	chunkSize := len(rawChunks[0])
	longProofSize := len(chunkProofs[len(chunkProofs)-1]) * cfg.HashSize
	shortProofSize := len(chunkProofs[0]) * cfg.HashSize
	opHeaderSize := len(cfg.OperationHeader)

	shortDatagramSize :=
		// 1-byte protocol header.
		1 +
			// Operation header.
			opHeaderSize +
			// uint16 for chunk index.
			2 +
			shortProofSize +
			// Raw chunk data.
			chunkSize

	// One datagram per raw chunk.
	datagrams := make([][]byte, n)

	var shortDatagramCount, longDatagramCount uint16
	if n&(n-1) == 0 {
		shortDatagramCount = n
	} else {
		// Otherwise, we need to calculate how many chunks didn't fit into the power of two.
		smallerPow2 := uint16(1 << (uint16(bits.Len16(n-1) - 1)))
		overflow := n - smallerPow2
		longDatagramCount = 2 * overflow
		shortDatagramCount = n - longDatagramCount
	}

	longDatagramSize := shortDatagramSize - shortProofSize + longProofSize

	// One single backing allocation for all the datagrams.
	// A single root object simplifies GC,
	// and the lifecycle of all datagrams is coupled together anyway.
	mem := make(
		[]byte,
		(int(shortDatagramSize)*int(shortDatagramCount))+(int(longDatagramSize)*int(longDatagramCount)),
	)

	for i := range rawChunks[:shortDatagramCount] {
		base := shortDatagramSize * i

		mem[base] = cfg.ProtocolID
		idx := base + 1

		copy(mem[idx:idx+opHeaderSize], cfg.OperationHeader)
		idx += opHeaderSize

		binary.BigEndian.PutUint16(mem[idx:idx+2], uint16(i))
		idx += 2

		// We don't include the proof length,
		// as the remote can infer it based on chunk index.
		for _, proof := range chunkProofs[i] {
			copy(mem[idx:idx+cfg.HashSize], proof)
			idx += cfg.HashSize
		}

		copy(mem[idx:idx+chunkSize], rawChunks[i])
		datagrams[i] = mem[base : idx+chunkSize]
	}

	longBase := int(shortDatagramCount) * int(shortDatagramSize)
	for j := range rawChunks[shortDatagramCount:] {
		base := longBase + (j * longDatagramSize)
		i := j + int(shortDatagramCount)

		mem[base] = cfg.ProtocolID
		idx := base + 1

		copy(mem[idx:idx+opHeaderSize], cfg.OperationHeader)
		idx += opHeaderSize

		binary.BigEndian.PutUint16(mem[idx:idx+2], uint16(i))
		idx += 2

		// We don't include the proof length,
		// as the remote can infer it based on chunk index.
		for _, proof := range chunkProofs[i] {
			copy(mem[idx:idx+cfg.HashSize], proof)
			idx += cfg.HashSize
		}

		copy(mem[idx:idx+chunkSize], rawChunks[i])
		datagrams[i] = mem[base : idx+chunkSize]
	}

	return datagrams
}
