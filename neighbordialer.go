package dragon

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/internal/dk"
	"github.com/gordian-engine/dragon/internal/dprotoi/dbootstrap/dbssendneighbor"
	"github.com/quic-go/quic-go"
)

// neighborDialer runs a dedicated goroutine for making neighbor requests.
// There are two cases where our node would make a neighbor request:
//  1. In reaction to a forward join message
//  2. In reaction to an active peer being disconnect
//
// This dedicated goroutine acts as a buffer between
// the kernel's view manager in case 1,
// or the kernel's active peer set in case 2,
// and the actual kernel.
// Doing the dial and bootstrap work in this goroutine
// reduces contention in those critical core components.
type neighborDialer struct {
	Log *slog.Logger

	Dialer dialer

	NeighborRequests <-chan string

	NewPeeringRequests chan<- dk.AddActivePeerRequest

	AdvertiseAddr string
	Cert          tls.Certificate
}

func (d *neighborDialer) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			d.Log.Info("Stopping due to context cancellation", "cause", context.Cause(ctx))
			return

		case addr := <-d.NeighborRequests:
			d.dialAndNeighbor(ctx, addr)
		}
	}
}

func (d *neighborDialer) dialAndNeighbor(ctx context.Context, addr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		d.Log.Warn(
			"Failed to resolve UDP address",
			"addr", addr,
			"err", err,
		)
		return
	}

	dr, err := d.Dialer.Dial(ctx, udpAddr)
	if err != nil {
		d.Log.Warn(
			"Failed to dial neighbor",
			"addr", addr,
			"err", err,
		)
	}

	chain, err := dcert.NewChainFromTLSConnectionState(dr.Conn.ConnectionState().TLS)
	if err != nil {
		d.Log.Warn(
			"Failed to extract certificate chain from neighbor",
			"addr", addr,
			"err", err,
		)
		return
	}

	// TODO: start a new goroutine for a context.WithCancelCause paired with notify.

	res, err := d.bootstrapNeighbor(ctx, dr.Conn)
	if err != nil {
		d.Log.Warn(
			"Failed to dial and bootstrap by neighbor",
			"addr", addr,
			"err", err,
		)
		return
	}

	// The bootstrap process completed successfully,
	// so now the last step is to confirm peering with the kernel.
	pResp := make(chan dk.AddActivePeerResponse, 1)
	req := dk.AddActivePeerRequest{
		QuicConn: dr.Conn,

		Chain: chain,

		AdmissionStream: res.Admission,

		Resp: pResp,
	}
	select {
	case <-ctx.Done():
		d.Log.Info(
			"Context canceled while sending peering request",
			"cause", context.Cause(ctx),
		)
		return

	case d.NewPeeringRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		d.Log.Info(
			"Context canceled while awaiting peering response",
			"cause", context.Cause(ctx),
		)
		return

	case resp := <-pResp:
		if resp.RejectReason != "" {
			// Last minute issue with adding the connection.
			// TODO: we should actually use a Disconnect message here,
			// since we have established all streams.
			if err := dr.Conn.CloseWithError(1, "TODO: peering rejected: "+resp.RejectReason); err != nil {
				d.Log.Debug("Failed to close connection", "err", err)
			}

			d.Log.Warn(
				"Failed to neighbor due to kernel rejecting peering",
				"addr", addr,
				"reason", resp.RejectReason,
			)
			return
		}

		// Otherwise it was accepted, and the Neighbor is complete.
		return
	}
}

func (d *neighborDialer) bootstrapNeighbor(
	ctx context.Context, qc quic.Connection,
) (dbssendneighbor.Result, error) {
	p := dbssendneighbor.Protocol{
		Log:  d.Log.With("protocol", "outgoing_bootstrap_neighbor"),
		Conn: qc,
		Cfg: dbssendneighbor.Config{
			AdvertiseAddr: d.AdvertiseAddr,
			Cert:          d.Cert,

			OpenStreamTimeout:         100 * time.Millisecond,
			AwaitNeighborReplyTimeout: 75 * time.Millisecond,

			NowFn: time.Now,
		},
	}

	res, err := p.Run(ctx)
	if err != nil {
		return res, fmt.Errorf("bootstrap by neighbor message failed: %w", err)
	}

	return res, nil
}
