package dbitset

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/golang/snappy"
	"github.com/gordian-engine/dragon/dquic"
)

type SnappyEncoder struct {
	// The byte slice representative of the bitset's Words.
	// If encoded through the AdaptiveEncoder,
	// it also has a 1-byte prefix of the [rawEncoding] header.
	wordBuf []byte

	// The snappy-encoded version of wordBuf,
	// prefixed with a big endian uint16 length.
	// If encoded through the AdaptiveEncoder,
	// it has a 3-byte prefix: 1 byte for the [snappyEncoding] header
	// and a uint16 length.
	encBuf []byte
}

func (e *SnappyEncoder) encode(
	bs *bitset.BitSet,
	adaptive bool,
) {
	words := bs.Words()
	nBytes := 8 * len(words)
	if adaptive {
		nBytes++
	}

	if cap(e.wordBuf) < nBytes {
		e.wordBuf = make([]byte, nBytes)
	} else {
		e.wordBuf = e.wordBuf[:nBytes]
	}

	// +2 for the size uint16.
	maxEnc := snappy.MaxEncodedLen(nBytes) + 2
	if adaptive {
		maxEnc++
	}

	if cap(e.encBuf) < maxEnc {
		e.encBuf = make([]byte, maxEnc)
	} else {
		e.encBuf = e.encBuf[:maxEnc]
	}
	encBuf := e.encBuf
	if adaptive {
		encBuf[0] = snappyEncoding
		encBuf = encBuf[1:]
	}

	// Copy the words first.
	wordBuf := e.wordBuf
	if adaptive {
		wordBuf[0] = rawEncoding
		wordBuf = wordBuf[1:]
	}
	for i, w := range words {
		// We use big endian in most encodings for human readability,
		// but in this case we use little endian
		// since it is more likely to match a modern machine's endianness.
		binary.LittleEndian.PutUint64(wordBuf[i*8:], w)
	}

	// Figure out how large the snappy encoding is,
	// then backfill the size header.
	res := snappy.Encode(encBuf[2:], wordBuf)
	binary.BigEndian.PutUint16(encBuf, uint16(len(res)))

	// Need to have the correct size of e.encBuf,
	// for when the bytes are sent.
	if adaptive {
		e.encBuf = e.encBuf[:3+len(res)]
	} else {
		e.encBuf = e.encBuf[:2+len(res)]
	}
}

func (e *SnappyEncoder) SendBitset(
	s dquic.SendStream,
	timeout time.Duration,
	bs *bitset.BitSet,
) error {
	e.encode(bs, false)

	return e.send(s, timeout)
}

func (e *SnappyEncoder) send(
	s dquic.SendStream,
	timeout time.Duration,
) error {
	if err := s.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
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
	s dquic.ReceiveStream,
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

	words := bs.Words()
	if len(words)*8 != decSz {
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

	// wb could have been nil on error;
	// that's why we used the temporary variable.
	d.wordBuf = wb

	for i := range words {
		words[i] = binary.LittleEndian.Uint64(d.wordBuf[i*8:])
	}

	return nil
}
