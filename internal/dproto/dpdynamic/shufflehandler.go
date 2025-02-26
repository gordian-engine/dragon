package dpdynamic

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

type shuffleHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h shuffleHandler) Handle(
	ctx context.Context, s quic.Stream, res *Result,
) (handler, error) {
	// We will inherit the previous read deadline from identifyStreamHandler, for now.

	// No message header necessary on this stream.
	// There is only one allowed message type anyway.
	var msg dproto.ShuffleMessage
	if err := msg.Decode(s); err != nil {
		return nil, fmt.Errorf("failed to decode shuffle message: %w", err)
	}

	res.ShuffleMessage = &msg

	// Now, there will be some more internal processing on this shuffle message,
	// and we will send back our reply.
	// But we will not read anything else on the stream.
	// Cancel the read side now so we can hopefully free some resources.
	// This seems like a good idea for now,
	// but it is also possible this is error-prone,
	// based on the subtleties in the stream cancellation in the QUIC docs.
	//
	// Need to think on this before deciding whether to enable it.
	// When canceled, the close call fails with message like "close called for canceled stream N".

	// s.CancelRead(1) // TODO: pick a meaningful code for this.

	return nil, nil
}

func (h shuffleHandler) Name() string {
	return "Shuffle Handler"
}
