package bci

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/quic-go/quic-go"
)

const (
	// Byte indicating that this is a re-sync of a missed datagram.
	datagramSyncMessageID byte = 0x01

	// Byte indicating that all datagrams have been sent.
	datagramsFinishedMessageID byte = 0xFF
)

// Constants for stream cancellation error codes.
const (
	GotFullDataErrorCode quic.StreamErrorCode = 0x607

	InterruptedErrorCode quic.StreamErrorCode = 0x11117
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
	appHeader []byte,
) ProtocolHeader {
	if len(appHeader) >= (1 << 16) {
		panic(fmt.Errorf(
			"BUG: application header is limited to %d bytes (got %d)",
			(1<<16)-1, len(appHeader),
		))
	}

	out := make([]byte, 1+len(broadcastID)+2)

	// The protocol ID is necessary so that a remote who receives the stream
	// can identify which application-layer protocol the message belongs to.
	out[0] = protocolID

	// The broadcast ID distinguishes multiple operations
	// within the same protocol.
	// Within a protocol, the broadcastID is a fixed length.
	copy(out[1:1+len(broadcastID)], broadcastID)

	// The last two bytes are the application header size.
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(appHeader)))

	return out
}

func (h ProtocolHeader) ProtocolID() byte {
	return h[0]
}

func (h ProtocolHeader) BroadcastID() []byte {
	return h[1 : len(h)-2]
}

// OpenStreamConfig is the config for [OpenStream].
type OpenStreamConfig struct {
	OpenStreamTimeout time.Duration
	SendHeaderTimeout time.Duration

	ProtocolHeader ProtocolHeader
	AppHeader      []byte

	Ratio byte
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

	// And finally we need to write our ratio byte.
	if _, err := s.Write([]byte{cfg.Ratio}); err != nil {
		return nil, fmt.Errorf("failed to write ratio byte for outgoing stream: %w", err)
	}

	// At this point of the protocol, we've done our announcement to the peer.
	// The peer must send us their "have" bitset before we can send anything else.
	return s, nil
}

// calculateRatio calculates the single-byte ratio
// indicating what fraction of the packets the current process has.
//
// While this is not yet used directly by a peer,
// we are making it part of the protocol now
// so that a peer has the capability to make decisions
// about which remotes to prioritize.
func calculateRatio(bs *bitset.BitSet) byte {
	c := bs.Count()
	if c == 0 {
		return 0
	}

	n := bs.Len()
	if c == n {
		// This should probably never happen,
		// but maybe it could if we cross the threshold as we start a relay.
		return 0xff
	}

	r := float32(c) / float32(n)
	r *= 256

	rb := uint8(r)
	switch rb {
	case 0:
		// Round up since we have more than zero.
		return 1
	case 0xff:
		// Round down since we don't have everything.
		return 0xfe
	default:
		return rb
	}
}

// SendSyncPacket writes the packet over the given stream.
func SendSyncPacket(
	s quic.SendStream,
	sendTimeout time.Duration,
	raw []byte,
) error {
	if err := s.SetWriteDeadline(time.Now().Add(sendTimeout)); err != nil {
		return fmt.Errorf(
			"failed to set write deadline for synchronous packet: %w", err,
		)
	}

	if _, err := s.Write(raw); err != nil {
		return fmt.Errorf(
			"failed to write synchronous packet data: %w", err,
		)
	}

	return nil
}

// SendSyncMissedDatagram sends an individual missed datagram
// as a synchronous packet over the given stream.
func SendSyncMissedDatagram(
	s quic.SendStream,
	sendTimeout time.Duration,
	raw []byte,
) error {
	if err := s.SetWriteDeadline(time.Now().Add(sendTimeout)); err != nil {
		return fmt.Errorf(
			"failed to set write deadline for synchronous datagram: %w", err,
		)
	}

	if _, err := s.Write([]byte{datagramSyncMessageID}); err != nil {
		return fmt.Errorf(
			"failed to write missed datagram message ID: %w", err,
		)
	}

	if _, err := s.Write(raw); err != nil {
		return fmt.Errorf(
			"failed to write synchronous missed datagram data: %w", err,
		)
	}

	return nil
}
