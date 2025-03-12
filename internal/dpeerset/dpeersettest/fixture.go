package dpeersettest

import (
	"context"
	"log/slog"
	"testing"

	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dmsg"
	"github.com/gordian-engine/dragon/internal/dpeerset"
	"github.com/gordian-engine/dragon/internal/dtest"
)

type Fixture struct {
	Log *slog.Logger

	Cfg dpeerset.ActiveViewConfig

	// Read-only channels for output from the active view.
	// The default values returned from NewFixture will all be 1-buffered
	// so active view operations don't block by default.
	// If you want to override the channels for a particular test,
	// change the field here and the corresponding one in Cfg too.
	ForwardJoinsFromNetwork <-chan dmsg.ForwardJoinFromNetwork
	ShufflesFromPeers       <-chan dmsg.ShuffleFromPeer
	ShuffleRepliesFromPeers <-chan dmsg.ShuffleReplyFromPeer
	ConnectionChanges       <-chan dconn.Change
}

func NewFixture(t *testing.T) *Fixture {
	t.Helper()

	log := dtest.NewLogger(t)

	forwardJoinsFromNetworkCh := make(chan dmsg.ForwardJoinFromNetwork, 1)
	shufflesFromPeersCh := make(chan dmsg.ShuffleFromPeer, 1)
	shuffleRepliesFromPeersCh := make(chan dmsg.ShuffleReplyFromPeer, 1)
	connectionChangesCh := make(chan dconn.Change, 1)

	cfg := dpeerset.ActiveViewConfig{
		// Skip Seeders and Workers, they can just use the default value.

		ForwardJoinsFromNetwork: forwardJoinsFromNetworkCh,

		ShufflesFromPeers:       shufflesFromPeersCh,
		ShuffleRepliesFromPeers: shuffleRepliesFromPeersCh,

		ConnectionChanges: connectionChangesCh,
	}

	return &Fixture{
		Log: log,
		Cfg: cfg,

		ForwardJoinsFromNetwork: forwardJoinsFromNetworkCh,
		ShufflesFromPeers:       shufflesFromPeersCh,
		ShuffleRepliesFromPeers: shuffleRepliesFromPeersCh,
		ConnectionChanges:       connectionChangesCh,
	}
}

func (f *Fixture) NewActiveView(ctx context.Context) *dpeerset.ActiveView {
	return dpeerset.NewActiveView(ctx, f.Log, f.Cfg)
}
