package breathcast

import (
	"context"
	"fmt"
	"io"
)

// broadcastDataReader is the [io.Reader]
// returned from [*BroadcastOperation.Data].
// It scans the completed datagrams from the [BroadcastOperation]
// and effectively concatenates their data into an io.Reader.
type broadcastDataReader struct {
	ctx context.Context
	op  *BroadcastOperation

	// How many bytes left to read.
	// Caller should initialize it as op.totalDataSize.
	// Necessary because the last datagram value most likely has padding.
	toRead int

	dIdx, dOffset int
}

func (r *broadcastDataReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, fmt.Errorf(
			"context canceled before broadcast data was ready: %w",
			context.Cause(r.ctx),
		)
	case <-r.op.dataReady:
		// Able to read everything now.
	}

	if r.toRead == 0 {
		return 0, io.EOF
	}

	// Every packet starts with some metadata but ends with the raw data.
	// The math is a bit simpler if we just count from the end,
	// because the metadata length can change
	// depending on the datagram index.
	curPacket := r.op.packets[r.dIdx]
	curData := curPacket[len(curPacket)-r.op.chunkSize+r.dOffset:]

	var n int
	for r.toRead > 0 && len(p) > 0 {
		readSz := min(
			len(curData), // Length of the current packet remaining.
			len(p),       // Length of output buffer.
			r.toRead,     // Total data left (relevant for last data (non-parity) packet).
		)

		nn := copy(p, curData[:readSz])
		p = p[nn:]
		n += nn
		r.dOffset += nn
		r.toRead -= nn

		if r.toRead == 0 {
			// Completely done, no need to bother with remaining bookkeeping.
			return n, nil
		}

		curData = curData[nn:]
		if len(curData) == 0 {
			// We already know there is data left to read,
			// so we can safely advance to the next datagram.
			r.dIdx++
			r.dOffset = 0
			curPacket := r.op.packets[r.dIdx]
			curData = curPacket[len(curPacket)-r.op.chunkSize:] // r.dOffset is zero already.
		}

		if len(p) == 0 {
			// Bookkeeping finished now, safe to return.
			return n, nil
		}
	}

	return n, nil
}
