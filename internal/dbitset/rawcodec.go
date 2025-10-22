package dbitset

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/dquic"
)

type RawEncoder struct {
	buf []byte
}

func (e *RawEncoder) encode(
	bs *bitset.BitSet,
	adaptive bool,
) {
	words := bs.Words()
	nBytes := 8 * len(words)
	if adaptive {
		nBytes++
	}

	if cap(e.buf) < nBytes {
		e.buf = make([]byte, nBytes)
	} else {
		e.buf = e.buf[:nBytes]
	}

	buf := e.buf
	if adaptive {
		buf[0] = rawEncoding
		buf = buf[1:]
	}

	for i, w := range words {
		// We use big endian in most encodings for human readability,
		// but in this case we use little endian
		// since it is more likely to match a modern machine's endianness.
		binary.LittleEndian.PutUint64(buf[i*8:], w)
	}
}

func (e *RawEncoder) SendBitset(
	s dquic.SendStream,
	timeout time.Duration,
	bs *bitset.BitSet,
) error {
	e.encode(bs, false)

	return e.send(s, timeout)
}

func (e *RawEncoder) send(
	s dquic.SendStream,
	timeout time.Duration,
) error {
	if err := s.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	if _, err := s.Write(e.buf); err != nil {
		return fmt.Errorf("failed to write raw bitset: %w", err)
	}

	return nil
}

type RawDecoder struct {
	buf []byte
}

func (d *RawDecoder) ReceiveBitset(
	s dquic.ReceiveStream,
	timeout time.Duration,
	bs *bitset.BitSet,
) error {
	words := bs.Words()
	nBytes := len(words) * 8
	if cap(d.buf) < nBytes {
		d.buf = make([]byte, nBytes)
	} else {
		d.buf = d.buf[:nBytes]
	}

	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if err := s.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set read deadline for raw bitset: %w", err)
	}
	if _, err := io.ReadFull(s, d.buf); err != nil {
		return fmt.Errorf("failed to read raw bitset data: %w", err)
	}
	for i := range words {
		words[i] = binary.LittleEndian.Uint64(d.buf[i*8:])
	}

	return nil
}
