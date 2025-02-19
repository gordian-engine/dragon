package dbsaj

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

type finishInitializingStreamsHandler struct {
	OuterLog *slog.Logger
	Cfg      *AcceptJoinConfig
}

func (h finishInitializingStreamsHandler) Handle(
	ctx context.Context, c quic.Connection, s quic.Stream, res *AcceptJoinResult,
) (acceptJoinHandler, error) {
	// It doesn't really matter what order we open the streams,
	// but we'll do Disconnect first since that happens to be declared first in the constants.

	deadline := h.Cfg.Now().Add(h.Cfg.InitializeStreamsTimeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	ds, err := c.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream for disconnect info: %w", err)
	}

	if err := ds.SetWriteDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set write deadline for disconnect stream: %w", err)
	}

	streamInit := [2]byte{
		dproto.CurrentProtocolVersion, byte(dproto.DisconnectStreamType),
	}
	if _, err := ds.Write(streamInit[:]); err != nil {
		return nil, fmt.Errorf("failed to write disconnect stream header: %w", err)
	}

	res.DisconnectStream = ds

	ss, err := c.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream for disconnect info: %w", err)
	}
	if err := ss.SetWriteDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set write deadline for shuffle stream: %w", err)
	}

	streamInit[1] = byte(dproto.ShuffleStreamType)
	if _, err := ss.Write(streamInit[:]); err != nil {
		return nil, fmt.Errorf("failed to write shuffle stream header: %w", err)
	}

	res.ShuffleStream = ss

	// We have initialized both streams.
	// There is nothing left to do in this protocol set.
	// Return control to the Node,
	// so that it can inform the kernel that we have opened streams to the peer.
	return nil, nil
}

func (h finishInitializingStreamsHandler) Name() string {
	return "Finish Initializing Streams"
}
