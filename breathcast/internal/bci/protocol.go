package bci

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/quic-go/quic-go"
)

// ProtocolHeader is a byte sequence containing:
//   - the protocol ID byte
//   - the broadcast ID, which is specific to the broadcast operation
//   - metadata for the application header
type ProtocolHeader []byte

// NewProtocolHeader returns a new ProtocolHeader with the given information.
func NewProtocolHeader(
	protocolID byte,
	broadcastID []byte,
	ratio byte,
	appHeader []byte,
) ProtocolHeader {
	if len(appHeader) >= (1 << 16) {
		panic(fmt.Errorf(
			"BUG: application header is limited to %d bytes (got %d)",
			(1<<16)-1, len(appHeader),
		))
	}

	out := make([]byte, 1+len(broadcastID)+3)

	// The protocol ID is necessary so that a remote who receives the stream
	// can identify which application-layer protocol the message belongs to.
	out[0] = protocolID

	// The broadcast ID distinguishes multiple operations
	// within the same protocol.
	// Within a protocol, the broadcastID is a fixed length.
	copy(out[1:1+len(broadcastID)], broadcastID)

	// The ratio indicates how much of the data we have already.
	out[1+len(broadcastID)] = ratio

	// The last two bytes are the application header size.
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(appHeader)))

	return out
}

// OpenStreamConfig is the config for [OpenStream].
type OpenStreamConfig struct {
	OpenStreamTimeout time.Duration
	SendHeaderTimeout time.Duration

	ProtocolHeader ProtocolHeader
	AppHeader      []byte
}

// OpenStream opens a new stream for the breathcast protocol.
func OpenStream(
	ctx context.Context,
	conn quic.Connection,
	cfg OpenStreamConfig,
) (quic.Stream, error) {
	openCtx, cancel := context.WithTimeout(ctx, cfg.OpenStreamTimeout)
	s, err := conn.OpenStreamSync(openCtx)
	cancel() // Immediately cancel sub-context to release resources.
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	if err := s.SetWriteDeadline(time.Now().Add(cfg.SendHeaderTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set write deadline for outgoing stream: %w", err)
	}

	if _, err := s.Write(cfg.ProtocolHeader); err != nil {
		return nil, fmt.Errorf("failed to write protocol header for outgoing stream: %w", err)
	}

	// Keep the write deadline for the application header data.
	if _, err := s.Write(cfg.AppHeader); err != nil {
		return nil, fmt.Errorf("failed to write application header for outgoing stream: %w", err)
	}

	// At this point of the protocol, we've done our announcement to the peer.
	// The peer must send us their "have" bitset before we can send anything else.
	return s, nil
}

// ReceiveBitset waits for a compressed bitset from the peer.
func ReceiveBitset(
	s quic.ReceiveStream,
	timeout time.Duration,
	n int,
	out *bitset.BitSet,
) error {
	// The peer must send us their compressed bitset.
	// There is a 4-byte header first:
	// uint16 for the number of set bits,
	// and another uint16 for the number of bytes for the combination index.
	var meta [4]byte

	if err := s.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to set read deadline for compressed bitset: %w", err)
	}
	if _, err := io.ReadFull(s, meta[:]); err != nil {
		return fmt.Errorf("failed to read bitset metadata: %w", err)
	}

	k := binary.BigEndian.Uint16(meta[:2])
	combIdxSize := binary.BigEndian.Uint16(meta[2:])

	combBytes := make([]byte, combIdxSize)
	if _, err := io.ReadFull(s, combBytes); err != nil {
		return fmt.Errorf("failed to read bitset data: %w", err)
	}
	var combIdx big.Int
	combIdx.SetBytes(combBytes)

	decodeCombinationIndex(n, int(k), &combIdx, out)

	return nil
}
