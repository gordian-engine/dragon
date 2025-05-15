package bci

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"

	"github.com/bits-and-blooms/bitset"
)

// PacketDecoder decodes a packet from an io.Reader
// (typically a [quic.ReceiveStream]).
//
// Methods on PacketDecoder are not safe for concurrent use.
type PacketDecoder struct {
	pid byte
	bid []byte

	nRootProofs uint
	hashSz      int

	chunkSz uint16

	prefixBuf []byte

	reserveNormalBuf, reserveSpilloverBuf []byte
}

// NewPacketDecoder returns a new PacketDecoder,
// for the given protocol and broadcast IDs.
func NewPacketDecoder(
	protocolID byte,
	broadcastID []byte,

	// The actual length of the root proofs slice.
	// So for cutoff tier 2,
	// this value would be 3, for instance.
	nRootProofs uint,
	hashSize int,
	chunkSize uint16,
) *PacketDecoder {
	return &PacketDecoder{
		pid: protocolID,
		bid: broadcastID,

		nRootProofs: nRootProofs,
		hashSz:      hashSize,

		chunkSz: chunkSize,

		prefixBuf: make([]byte, 1+len(broadcastID)+2),
	}
}

// PacketDecodeResult is the result type for [*PacketDecoder.Decode].
type PacketDecodeResult struct {
	// Number of bytes read during call to Decode.
	N int

	// Raw packet bytes.
	Raw []byte

	// Parsed packet that references the Raw field's bytes.
	Packet BroadcastPacket
}

// Decode reads a single packet from r.
//
// The havePackets argument is used to avoid allocations
// if attempting to parse a packet we've seen before.
// In that case, the returned error will be of type [AlreadyHadPacketError].
func (d *PacketDecoder) Decode(
	r io.Reader, havePackets *bitset.BitSet,
) (PacketDecodeResult, error) {
	// First, we use the prefix buffer to validate the packet prefix.
	var res PacketDecodeResult
	var err error

	res.N, err = io.ReadFull(r, d.prefixBuf)
	if err != nil {
		return res, fmt.Errorf(
			"failed to read packet prefix: %w", err,
		)
	}

	if d.pid != d.prefixBuf[0] {
		return res, fmt.Errorf(
			"expected prefix byte 0x%x, got 0x%x --- %x (%d)",
			d.pid, d.prefixBuf[0], d.prefixBuf, len(d.prefixBuf),
		)
	}

	gotPrefix := d.prefixBuf[1 : 1+len(d.bid)]
	if !bytes.Equal(d.bid, gotPrefix) {
		return res, fmt.Errorf(
			"expected broadcast ID %x, got %x",
			d.bid, gotPrefix,
		)
	}

	chunkIdx := binary.BigEndian.Uint16(d.prefixBuf[len(d.prefixBuf)-2:])
	nChunks := uint16(havePackets.Len())
	if chunkIdx >= nChunks {
		return res, fmt.Errorf(
			"chunk index %d exceeds bounds of %d",
			chunkIdx, nChunks-1,
		)
	}

	// Now calculate how many proofs we need.
	// Assuming it's more efficient to keep these few operations here
	// than to store a few extra values on d.
	treeHeight := bits.Len16(nChunks)
	nProofs := treeHeight - bits.Len(d.nRootProofs)
	isSpillover := false
	if hasSpillover := nChunks&(nChunks-1) != 0; hasSpillover {
		treeHeight++
		spilloverCount := nChunks - uint16(1<<(treeHeight-2))
		if chunkIdx >= nChunks-(spilloverCount*2) {
			nProofs++
			isSpillover = true
		}
	}

	proofsLen := int(nProofs) * d.hashSz

	if havePackets.Test(uint(chunkIdx)) {
		// We had this packet already.
		n, err := io.CopyN(io.Discard, r, int64(proofsLen)+int64(d.chunkSz))
		res.N += int(n)
		if err != nil {
			return res, fmt.Errorf(
				"failed to discard already-known packet: %w", err,
			)
		}
		return res, AlreadyHadPacketError{ChunkIndex: chunkIdx}
	}

	// We didn't have the packet, so now we need to reserve space for it.
	var buf []byte
	if isSpillover && d.reserveSpilloverBuf != nil {
		buf = d.reserveSpilloverBuf
		d.reserveSpilloverBuf = nil
	} else if !isSpillover && d.reserveNormalBuf != nil {
		buf = d.reserveNormalBuf
		d.reserveNormalBuf = nil
	} else {
		sz := len(d.prefixBuf) + proofsLen + int(d.chunkSz)
		buf = make([]byte, sz)
	}

	// Read in the proofs and data first, as this could fail.
	n, err := io.ReadFull(r, buf[len(d.prefixBuf):])
	res.N += n
	if err != nil {
		// We allocated the buffer so put it in reserve.
		if isSpillover {
			d.reserveSpilloverBuf = buf
		} else {
			d.reserveNormalBuf = buf
		}
		return res, fmt.Errorf(
			"failed to read full packet: %w", err,
		)
	}

	// Now backfill the header portion.
	_ = copy(buf, d.prefixBuf)

	res.Raw = buf

	// Finally, fill in the broadcast packet.
	var p BroadcastPacket
	p.BroadcastID = buf[1 : 1+len(d.prefixBuf)-2]
	p.ChunkIndex = chunkIdx

	proofs := make([][]byte, nProofs)
	idxOffset := len(d.prefixBuf)
	for i := range proofs {
		proofs[i] = buf[idxOffset : idxOffset+d.hashSz]
		idxOffset += d.hashSz
	}
	p.Proofs = proofs

	p.Data = buf[idxOffset:]

	res.Packet = p

	return res, nil
}

// AlreadyHadPacketError is the error value returned
// from [*PacketDecoder.Decode] if its bitset indicates
// that the system already knows about the given chunk.
type AlreadyHadPacketError struct {
	ChunkIndex uint16
}

func (e AlreadyHadPacketError) Error() string {
	return fmt.Sprintf(
		"attempted to decode already-known packet with chunk index %d",
		e.ChunkIndex,
	)
}
