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
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dmsg"
	"github.com/quic-go/quic-go"
)

type IntegrationApp struct {
	log *slog.Logger

	Breathcast *breathcast.Protocol

	// Channel for tests to read, indicating a new broadcast operation.
	IncomingBroadcasts chan IncomingBroadcast

	// Internal channel for parsed streams.
	// The main loop has to decide whether to create a new operation
	// or return an existing one.
	incoming chan incomingBroadcastRequest

	// Channel for datagram packets.
	newPackets chan newPacketRequest

	connectedNodesRequests chan (chan<- []int)

	originations chan originationRegistration
}

type incomingBroadcastRequest struct {
	AppHeader BroadcastAppHeader
	Resp      chan incomingBroadcastResponse
}

type incomingBroadcastResponse struct {
	Op    *breathcast.BroadcastOperation
	IsNew bool
}

type newPacketRequest struct {
	BroadcastID string
	Raw         []byte
}

type originationRegistration struct {
	BroadcastID string
	Op          *breathcast.BroadcastOperation
}

const breathcastProtocolID = 0x90

func NewIntegrationApp(
	t *testing.T,
	ctx context.Context,
	log *slog.Logger,
	connChanges <-chan dconn.Change,
	nodeIDsByLeafCert map[dcert.LeafCertHandle]int,
) *IntegrationApp {
	t.Helper()

	appDone := make(chan struct{})

	t.Cleanup(func() {
		<-appDone
	})

	connStream := dpubsub.NewStream[dconn.Change]()

	app := &IntegrationApp{
		log: log,

		Breathcast: breathcast.NewProtocol(
			ctx,
			log.With("p", "breathcast"),
			breathcast.ProtocolConfig{
				InitialConnections: nil,

				ConnectionChanges: connStream,

				ProtocolID: breathcastProtocolID,

				BroadcastIDLength: 4, // Format: bc##.
			},
		),

		IncomingBroadcasts: make(chan IncomingBroadcast, 1),

		// Arbitrary size -- ought to be sufficiently large this way.
		incoming: make(chan incomingBroadcastRequest, 8),

		newPackets: make(chan newPacketRequest, 16),

		// Unbuffered is fine here, to synchronize on the ConnectedNodes method.
		connectedNodesRequests: make(chan (chan<- []int)),

		originations: make(chan originationRegistration),
	}

	go app.mainLoop(ctx, appDone, connChanges, connStream, nodeIDsByLeafCert)

	return app
}

func (a *IntegrationApp) mainLoop(
	ctx context.Context,
	done chan<- struct{},
	changes <-chan dconn.Change,
	mc *dpubsub.Stream[dconn.Change],
	nodeIDsByLeafCert map[dcert.LeafCertHandle]int,
) {
	defer close(done)

	var wg sync.WaitGroup

	conns := map[dcert.LeafCertHandle]dquic.Conn{}

	ops := map[string]*breathcast.BroadcastOperation{}

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return

		case cc := <-changes:
			if cc.Adding {
				conns[cc.Conn.Chain.LeafHandle] = cc.Conn.QUIC
				wg.Add(2)
				go a.acceptStreams(ctx, &wg, cc.Conn)
				go a.acceptDatagrams(ctx, &wg, cc.Conn)
			} else {
				delete(conns, cc.Conn.Chain.LeafHandle)
			}

			mc.Publish(cc)
			mc = mc.Next

		case req := <-a.incoming:
			ah := req.AppHeader
			op, ok := ops[string(ah.BroadcastID)]
			if !ok {
				var err error
				op, err = a.Breathcast.NewIncomingBroadcast(
					ctx, ah.ToIncomingBroadcastConfig(),
				)
				if err != nil {
					if errors.Is(err, context.Canceled) {
						// Handle on next iteration.
						continue
					}

					panic(err)
				}
				ops[string(ah.BroadcastID)] = op
			}

			// Safe to assume response channel is buffered.
			req.Resp <- incomingBroadcastResponse{
				Op:    op,
				IsNew: !ok,
			}

		case req := <-a.newPackets:
			op := ops[req.BroadcastID]
			if op == nil {
				panic(fmt.Errorf(
					"BUG: got a packet for an unknown broadcast ID %q",
					req.BroadcastID,
				))
			}

			if err := op.HandlePacket(ctx, req.Raw); err != nil {
				if errors.Is(err, context.Canceled) {
					// Handle on next iteration.
					continue
				}
				panic(err)
			}

		case req := <-a.connectedNodesRequests:
			out := make([]int, 0, len(conns))
			for k := range conns {
				out = append(out, nodeIDsByLeafCert[k])
			}

			req <- out

		case reg := <-a.originations:
			if _, ok := ops[reg.BroadcastID]; ok {
				panic(fmt.Errorf(
					"BUG: attempted to register origination for existing broadcast ID %q",
					reg.BroadcastID,
				))
			}

			ops[reg.BroadcastID] = reg.Op
		}
	}
}

func (a *IntegrationApp) RegisterOrigination(
	ctx context.Context,
	bid string,
	op *breathcast.BroadcastOperation,
) error {
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case a.originations <- originationRegistration{
		BroadcastID: bid,
		Op:          op,
	}:
		// Unbuffered channel, no acknowledgement required.
		return nil
	}
}

func (a *IntegrationApp) ConnectedNodes() []int {
	req := make(chan []int, 1)
	a.connectedNodesRequests <- req
	return <-req
}

func (a *IntegrationApp) acceptStreams(
	ctx context.Context,
	wg *sync.WaitGroup,
	conn dconn.Conn,
) {
	defer wg.Done()

	for {
		s, err := conn.QUIC.AcceptStream(ctx)
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
				var appError *quic.ApplicationError
				if errors.As(err, &appError) && dquic.ApplicationErrorCode(appError.ErrorCode) == dmsg.RemovingFromActiveView {
					return
				}

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
			appHeader.Raw = jah
			appHeader.BroadcastID = bid

			// We need to send the app header back to the main loop,
			// and the main loop will return a broadcast operation.
			respCh := make(chan incomingBroadcastResponse, 1)
			select {
			case <-ctx.Done():
				return
			case a.incoming <- incomingBroadcastRequest{
				AppHeader: appHeader,
				Resp:      respCh,
			}:
				// Okay, keep going.
			}

			var resp incomingBroadcastResponse
			select {
			case <-ctx.Done():
				return
			case resp = <-respCh:
				// Okay.
			}

			// And accept the broadcast.
			if err := resp.Op.AcceptBroadcast(
				ctx, conn, s,
			); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				panic(err)
			}

			// Announce we have received an incoming broadcast,
			// only if this was a new broadcast operation.
			if resp.IsNew {
				select {
				case <-ctx.Done():
					// Quit.
					return
				case a.IncomingBroadcasts <- IncomingBroadcast{
					BroadcastID: bid,
					AppHeader:   jah,
					Stream:      s,

					Op: resp.Op,
				}:
					// Keep going.
				}
			}

		default:
			panic(fmt.Errorf(
				"unrecognized protocol ID 0x%x", protoByte[0],
			))
		}
	}
}

func (a *IntegrationApp) acceptDatagrams(
	ctx context.Context,
	wg *sync.WaitGroup,
	conn dconn.Conn,
) {
	defer wg.Done()

	for {
		b, err := conn.QUIC.ReceiveDatagram(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}

			var appError *quic.ApplicationError
			if errors.As(err, &appError) && dquic.ApplicationErrorCode(appError.ErrorCode) == dmsg.RemovingFromActiveView {
				return
			}

			panic(err)
		}

		bid := a.Breathcast.ExtractPacketBroadcastID(b)
		if len(bid) == 0 {
			continue
		}

		select {
		case <-ctx.Done():
			return
		case a.newPackets <- newPacketRequest{
			BroadcastID: string(bid),
			Raw:         b,
		}:
			// Okay.
		}
	}
}

type IncomingBroadcast struct {
	BroadcastID, AppHeader []byte
	Stream                 dquic.Stream

	Op *breathcast.BroadcastOperation
}

// BroadcastAppHeader is the app header used for broadcasts.
// This is simply JSON encoded for the test.
// Production code would likely use a more efficient encoding,
// and it would include more fields for application-level decisions.
type BroadcastAppHeader struct {
	BroadcastID []byte

	Raw []byte

	NData, NParity uint16

	TotalDataSize int

	HashNonce []byte

	RootProofs [][]byte

	ChunkSize uint16
}

func (h BroadcastAppHeader) ToIncomingBroadcastConfig() breathcast.IncomingBroadcastConfig {
	return breathcast.IncomingBroadcastConfig{
		BroadcastID: h.BroadcastID,

		AppHeader: h.Raw,

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
