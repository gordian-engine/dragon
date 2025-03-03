package dprotoi

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/gordian-engine/dragon/daddr"
	"github.com/gordian-engine/dragon/dcert"
)

// ShuffleMessage is the outgoing message
// when a node initiates a shuffle.
type ShuffleMessage struct {
	Entries []ShuffleEntry
}

func (m ShuffleMessage) Encode(w io.Writer) error {
	return encodeShuffle(ShuffleMessageType, m.Entries, w)
}

// EncodeBare encodes the message without a type header.
func (m ShuffleMessage) EncodeBare(w io.Writer) error {
	const skipTypeHeader = 0xff
	return encodeShuffle(skipTypeHeader, m.Entries, w)
}

func (m *ShuffleMessage) Decode(r io.Reader) error {
	entries, err := decodeShuffle(r)
	if err != nil {
		return err
	}

	m.Entries = entries
	return nil
}

// ShuffleReplyMessage is the reply to a [ShuffleMessage].
type ShuffleReplyMessage struct {
	Entries []ShuffleEntry
}

func (m ShuffleReplyMessage) Encode(w io.Writer) error {
	return encodeShuffle(ShuffleMessageType, m.Entries, w)
}

// EncodeBare encodes the message without a type header.
func (m ShuffleReplyMessage) EncodeBare(w io.Writer) error {
	const skipTypeHeader = 0xff
	return encodeShuffle(skipTypeHeader, m.Entries, w)
}

func (m *ShuffleReplyMessage) Decode(r io.Reader) error {
	entries, err := decodeShuffle(r)
	if err != nil {
		return err
	}

	m.Entries = entries
	return nil
}

// ShuffleEntry contains an address attestation
// and a certificate chain.
type ShuffleEntry struct {
	AA    daddr.AddressAttestation
	Chain dcert.Chain
}

func encodeShuffle(
	msgType MessageType,
	entries []ShuffleEntry,
	w io.Writer,
) error {
	if len(entries) == 0 {
		panic(errors.New("BUG: attempted to encode empty shuffle message"))
	}
	// Not sure what is a reasonable limit yet,
	// so just pick the largest value we can fit in one byte.
	const maxEntries = 255
	if len(entries) > maxEntries {
		panic(fmt.Errorf(
			"ILLEGAL: attempted to encode shuffle with too many entries: got %d, limit is %d",
			len(entries), maxEntries,
		))
	}

	// Calculate required buffer size first.
	// Shuffles are expected to happen relatively infrequently,
	// so it seems unlikely that it will be worth using a pool.

	sz := 2 // Message type and number of entries.

	for _, e := range entries {
		// Order doesn't matter while we accumulate sizes.
		sz += e.AA.EncodedSize() + e.Chain.EncodedSize()
	}

	buf := bytes.NewBuffer(make([]byte, 0, sz))
	if msgType != 0xff {
		// Temporary workaround to enable EncodeBare.
		// We may end up never needing a header for this message.
		_ = buf.WriteByte(byte(msgType))
	}
	_ = buf.WriteByte(byte(len(entries)))

	for _, e := range entries {
		// The AA cannot fail when encoding to a bytes.Buffer.

		// Note, aa.Encode currently allocates internally,
		// which is likely going to cause a double allocation here.
		// If this shows up in profiling then we should add another method to aa,
		// perhaps accepting a *bytes.Buffer,
		// and which understands it does not need a temporary byte slice in between.
		_ = e.AA.Encode(buf)

		// Likewise with the encoded Chain.
		_ = e.Chain.Encode(buf)
	}

	_, err := buf.WriteTo(w)
	return err
}

func decodeShuffle(r io.Reader) ([]ShuffleEntry, error) {
	// Assume the message type byte has already been read by the caller.

	// Read the number of entries for the map.
	var szBuf [1]byte
	if _, err := io.ReadFull(r, szBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to read number of shuffle entries: %w", err)
	}

	remaining := uint8(szBuf[0])
	if remaining == 0 {
		return nil, errors.New("decoded invalid shuffle entry count of zero")
	}

	out := make([]ShuffleEntry, remaining)

	for i := range out {
		var e ShuffleEntry
		if err := e.AA.Decode(r); err != nil {
			return nil, fmt.Errorf(
				"failed to decode address attestation for shuffle entry: %w", err,
			)
		}
		if err := e.Chain.Decode(r); err != nil {
			return nil, fmt.Errorf(
				"failed to decode chain for shuffle entry: %w", err,
			)
		}

		out[i] = e
	}

	return out, nil
}
