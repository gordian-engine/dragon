package dbitset

import (
	"fmt"
	"io"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/dquic"
)

const (
	rawEncoding         byte = 0
	snappyEncoding      byte = 1
	combinationEncoding byte = 2
)

type AdaptiveEncoder struct {
	se SnappyEncoder
	ce CombinationEncoder
}

func (e *AdaptiveEncoder) SendBitset(
	s dquic.SendStream,
	timeout time.Duration,
	bs *bitset.BitSet,
) error {
	if e.useCombination(bs) {
		e.ce.encode(bs, true)
		return e.ce.send(s, timeout)
	}

	// Otherwise attempt snappy encoding
	// and see if we save any bytes.
	e.se.encode(bs, true)

	// The remote end knows the size of the bitset up front,
	// so raw bytes can be sent directly.
	// But we have a two-byte size overhead for snappy encoding,
	// since the remote cannot know the encoded size.
	if len(e.se.wordBuf) < len(e.se.encBuf)+2 {
		// The wordBuf we allocated in the snappy encoder
		// can be dropped directly into a raw encoder,
		// since we used the "adaptive" encoding.
		re := RawEncoder{buf: e.se.wordBuf}
		return re.send(s, timeout)
	}

	return e.se.send(s, timeout)
}

func (e *AdaptiveEncoder) useCombination(bs *bitset.BitSet) bool {
	// TODO: we need to gather real data
	// to determine appropriate bounds for using a combination encoding.
	// These rough estimates were produced from some
	// ad hoc one-off tests.
	return bs.Len() < 512 || bs.Count() < 32
}

type AdaptiveDecoder struct {
	sd SnappyDecoder
	cd CombinationDecoder
	rd RawDecoder
}

func (d *AdaptiveDecoder) ReceiveBitset(
	s dquic.ReceiveStream,
	timeout time.Duration,
	bs *bitset.BitSet,
) error {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if err := s.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set read deadline for adaptive bitset: %w", err)
	}

	var h [1]byte
	if _, err := io.ReadFull(s, h[:]); err != nil {
		return fmt.Errorf("failed to read type header for adaptive bitset: %w", err)
	}

	// TODO: these are re-setting the deadline, but they shouldn't.
	switch h[0] {
	case rawEncoding:
		// Always borrow the snappy decoder's word buffer.
		d.rd.buf = d.sd.wordBuf
		err := d.rd.ReceiveBitset(s, timeout, bs)
		d.sd.wordBuf = d.rd.buf
		return err
	case snappyEncoding:
		return d.sd.ReceiveBitset(s, timeout, bs)
	case combinationEncoding:
		return d.cd.ReceiveBitset(s, timeout, bs)
	default:
		return fmt.Errorf(
			"unknown adaptive header byte 0x%x", h[0],
		)
	}
}
