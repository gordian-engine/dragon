package dbitset

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/golang/snappy"
	"github.com/quic-go/quic-go"
)

type SnappyEncoder struct {
	// The byte slice representative of the bitset's Words.
	wordBuf []byte

	// The snappy-encoded version of wordBuf.
	encBuf []byte
}

func (e *SnappyEncoder) SendBitset(
	s quic.SendStream,
	timeout time.Duration,
	bs *bitset.BitSet,
) error {
	words := bs.Words()
	nBytes := 8 * len(words)

	if cap(e.wordBuf) < nBytes {
		e.wordBuf = make([]byte, nBytes)
	} else {
		e.wordBuf = e.wordBuf[:nBytes]
	}

	maxEnc := snappy.MaxEncodedLen(len(e.wordBuf))
	if cap(e.encBuf) < maxEnc {
		e.encBuf = make([]byte, maxEnc)
	} else {
		e.encBuf = e.encBuf[:maxEnc]
	}

	// Copy the words first.
	for i, w := range words {
		binary.LittleEndian.PutUint64(e.wordBuf[i*8:], w)
	}
	e.encBuf = snappy.Encode(e.encBuf, e.wordBuf)

	// If it were 65k bits,
	// that would encode losslessly into 8k bytes.
	// So even if this ends up with maximal snappy overhead,
	// the length will still fit in a uint16.
	var meta [2]byte
	binary.BigEndian.PutUint16(meta[:], uint16(len(e.encBuf)))

	if err := s.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	if _, err := s.Write(meta[:]); err != nil {
		return fmt.Errorf("failed to write snappy bitset length: %w", err)
	}

	if _, err := s.Write(e.encBuf); err != nil {
		return fmt.Errorf("failed to write snappy bitset: %w", err)
	}

	return nil
}

type SnappyDecoder struct {
	// Holds the snappy-encoded bytes.
	encBuf []byte

	// The snappy-decoded bytes,
	// to be interpreted as uint64s to back the bitset's Words.
	wordBuf []byte
}

func (d *SnappyDecoder) ReceiveBitset(
	s quic.ReceiveStream,
	timeout time.Duration,
	bs *bitset.BitSet,
) error {
	if cap(d.encBuf) < 2 {
		// Probably uninitialized.
		// Allocate a bit larger here,
		// since we have to parse the length
		// before we can right-size encBuf.
		d.encBuf = make([]byte, 2, 128)
	} else {
		d.encBuf = d.encBuf[:2]
	}

	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if err := s.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set read deadline for raw bitset: %w", err)
	}

	if _, err := io.ReadFull(s, d.encBuf); err != nil {
		return fmt.Errorf("failed to read snappy length for bitset: %w", err)
	}

	encSz := binary.BigEndian.Uint16(d.encBuf)
	// TODO: reject if encSz is too large:
	// we can determine the upper bound for a 65k bitset.

	if cap(d.encBuf) < int(encSz) {
		d.encBuf = make([]byte, encSz)
	} else {
		d.encBuf = d.encBuf[:encSz]
	}

	if _, err := io.ReadFull(s, d.encBuf); err != nil {
		return fmt.Errorf("failed to read snappy-encoded bitset: %w", err)
	}

	decSz, err := snappy.DecodedLen(d.encBuf)
	if err != nil {
		return fmt.Errorf("failed to calculate snappy-decoded bitset length: %w", err)
	}

	if len(bs.Words())*8 != decSz {
		return fmt.Errorf(
			"calculated decoded size of %d bytes but expected %d",
			decSz, len(bs.Words())*8,
		)
	}

	// Don't need to size d.wordBuf; that will happen in snappy.Decode.

	wb, err := snappy.Decode(d.wordBuf, d.encBuf)
	if err != nil {
		return fmt.Errorf(
			"failed to decode snappy bitset: %w", err,
		)
	}

	// wb could have been nil on error.
	d.wordBuf = wb

	if err := binary.Read(
		bytes.NewReader(d.wordBuf),
		binary.LittleEndian,
		bs.Words(),
	); err != nil {
		return fmt.Errorf(
			"failed to parse bytes for bitset: %w", err,
		)
	}

	return nil
}
