package dbitset

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/quic-go/quic-go"
)

type RawEncoder struct{}

func (RawEncoder) SendBitset(
	s quic.SendStream,
	timeout time.Duration,
	bs *bitset.BitSet,
) error {
	if err := s.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	if err := binary.Write(s, binary.LittleEndian, bs.Words()); err != nil {
		return fmt.Errorf("failed to write raw bitset: %w", err)
	}

	return nil
}

type RawDecoder struct{}

func (RawDecoder) ReceiveBitset(
	s quic.ReceiveStream,
	timeout time.Duration,
	bs *bitset.BitSet,
) error {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if err := s.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set read deadline for raw bitset: %w", err)
	}
	if err := binary.Read(s, binary.LittleEndian, bs.Words()); err != nil {
		return fmt.Errorf("failed to read raw bitset data: %w", err)
	}

	return nil
}
