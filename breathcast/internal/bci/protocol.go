package bci

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

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

// SendSyncPacket writes the packet over the given stream.
func SendSyncPacket(
	s quic.SendStream,
	sendTimeout time.Duration,
	chunkIdx uint16,
	raw []byte,
) error {
	if len(raw) > (1<<16)-1 {
		panic(fmt.Errorf(
			"BUG: packet size must fit in uint16 (got length %d)",
			len(raw),
		))
	}

	if err := s.SetWriteDeadline(time.Now().Add(sendTimeout)); err != nil {
		return fmt.Errorf(
			"failed to set write deadline for synchronous packet: %w", err,
		)
	}

	var meta [4]byte
	binary.BigEndian.PutUint16(meta[:2], chunkIdx)
	binary.BigEndian.PutUint16(meta[2:], uint16(len(raw)))

	if _, err := s.Write(meta[:]); err != nil {
		return fmt.Errorf(
			"failed to write synchronous packet metadata: %w", err,
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
	chunkIdx uint16,
	raw []byte,
) error {
	if len(raw) > (1<<16)-1 {
		panic(fmt.Errorf(
			"BUG: datagram size must fit in uint16 (got length %d)",
			len(raw),
		))
	}

	if err := s.SetWriteDeadline(time.Now().Add(sendTimeout)); err != nil {
		return fmt.Errorf(
			"failed to set write deadline for synchronous datagram: %w", err,
		)
	}

	var meta [5]byte
	meta[0] = datagramSyncMessageID
	binary.BigEndian.PutUint16(meta[1:3], chunkIdx)
	binary.BigEndian.PutUint16(meta[3:], uint16(len(raw)))

	if _, err := s.Write(meta[:]); err != nil {
		return fmt.Errorf(
			"failed to write synchronous missed datagram metadata: %w", err,
		)
	}

	if _, err := s.Write(raw); err != nil {
		return fmt.Errorf(
			"failed to write synchronous missed datagram data: %w", err,
		)
	}

	return nil
}
