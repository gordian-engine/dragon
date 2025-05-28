package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/quic-go/quic-go"
)

type IntegrationApp struct {
	log *slog.Logger

	Breathcast *breathcast.Protocol

	IncomingBroadcasts chan IncomingBroadcast
}

const breathcastProtocolID = 0x90

func NewIntegrationApp(
	t *testing.T,
	ctx context.Context,
	log *slog.Logger,
	connChanges <-chan dconn.Change,
) *IntegrationApp {
	t.Helper()

	appDone := make(chan struct{})

	t.Cleanup(func() {
		<-appDone
	})

	connMulticast := dchan.NewMulticast[dconn.Change]()

	app := &IntegrationApp{
		log: log,

		Breathcast: breathcast.NewProtocol(
			ctx,
			log.With("p", "breathcast"),
			breathcast.ProtocolConfig{
				InitialConnections: nil,

				ConnectionChanges: connMulticast,

				ProtocolID: breathcastProtocolID,

				BroadcastIDLength: 4, // Format: bc##.
			},
		),

		IncomingBroadcasts: make(chan IncomingBroadcast, 1),
	}

	go app.mainLoop(ctx, appDone, connChanges, connMulticast)

	return app
}

func (a *IntegrationApp) mainLoop(
	ctx context.Context,
	done chan<- struct{},
	changes <-chan dconn.Change,
	mc *dchan.Multicast[dconn.Change],
) {
	defer close(done)

	var wg sync.WaitGroup

	conns := map[string]quic.Connection{}

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return

		case cc := <-changes:
			if cc.Adding {
				conns[string(cc.Conn.Chain.Leaf.RawSubjectPublicKeyInfo)] = cc.Conn.QUIC
				wg.Add(1)
				go a.acceptStreams(ctx, &wg, cc.Conn.QUIC)
			} else {
				delete(conns, string(cc.Conn.Chain.Leaf.RawSubjectPublicKeyInfo))
			}

			mc.Set(cc)
			mc = mc.Next
		}
	}
}

func (a *IntegrationApp) acceptStreams(
	ctx context.Context,
	wg *sync.WaitGroup,
	conn quic.Connection,
) {
	defer wg.Done()

	for {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			panic(err)
		}

		// Extract protocol byte.
		var protoByte [1]byte
		if _, err := io.ReadFull(s, protoByte[:]); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			panic(err)
		}

		switch protoByte[0] {
		case breathcastProtocolID:
			bid, err := a.Breathcast.ExtractStreamBroadcastID(s, nil)
			if err != nil {
				panic(err)
			}
			jah, _, err := breathcast.ExtractStreamApplicationHeader(s, nil)
			if err != nil {
				panic(err)
			}

			var appHeader BroadcastAppHeader
			if err := json.Unmarshal(jah, &appHeader); err != nil {
				panic(err)
			}

			// Announce we are receiving an incoming broadcast.
			select {
			case <-ctx.Done():
				// Quit.
				return
			case a.IncomingBroadcasts <- IncomingBroadcast{
				BroadcastID: bid,
				AppHeader:   jah,
				Stream:      s,
			}:
				// Keep going.
			}

			// Now accept the incoming broadcast.
			bop, err := a.Breathcast.NewIncomingBroadcast(
				ctx, appHeader.ToIncomingBroadcastConfig(bid, jah),
			)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				panic(err)
			}
			_ = bop

		default:
			panic(fmt.Errorf(
				"unrecognized protocol ID 0x%x", protoByte[0],
			))
		}
	}
}

type IncomingBroadcast struct {
	BroadcastID, AppHeader []byte
	Stream                 quic.Stream
}

// BroadcastAppHeader is the app header used for broadcasts.
// This is simply JSON encoded for the test.
// Production code would likely use a more efficient encoding,
// and it would include more fields for application-level decisions.
type BroadcastAppHeader struct {
	NData, NParity uint16

	TotalDataSize int

	HashNonce []byte

	RootProofs [][]byte

	ChunkSize uint16
}

func (h BroadcastAppHeader) ToIncomingBroadcastConfig(
	broadcastID, appHeader []byte,
) breathcast.IncomingBroadcastConfig {
	return breathcast.IncomingBroadcastConfig{
		BroadcastID: broadcastID,

		AppHeader: appHeader,

		NData:   h.NData,
		NParity: h.NParity,

		TotalDataSize: h.TotalDataSize,

		Hasher:    bcsha256.Hasher{},
		HashSize:  bcsha256.HashSize,
		HashNonce: h.HashNonce,

		RootProofs: h.RootProofs,

		ChunkSize: h.ChunkSize,
	}
}
