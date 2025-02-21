package dragon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/dca"
	"github.com/gordian-engine/dragon/internal/dk"
	"github.com/gordian-engine/dragon/internal/dproto/dbsneighbor"
	"github.com/quic-go/quic-go"
)

type neighborDialer struct {
	Log *slog.Logger

	BaseTLSConf *tls.Config

	CAPool *dca.Pool

	QUICConf      *quic.Config
	QUICTransport *quic.Transport

	NeighborRequests <-chan string

	NewPeeringRequests chan<- dk.NewPeeringRequest
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

	// TODO: extract dialer type from all this.
	// ---- beginning of code copied from (*Node).DialAndJoin
	tlsConf := d.BaseTLSConf.Clone()
	tlsConf.RootCAs = d.CAPool.CertPool()

	qc, err := d.QUICTransport.Dial(ctx, udpAddr, tlsConf, d.QUICConf)
	if err != nil {
		d.Log.Warn(
			"Failed to dial desired neighbor",
			"addr", addr,
			"err", err,
		)
		return
	}

	// Now that we have a raw connection to that peer,
	// we need to ensure that we close it if that certificate is removed.
	vcs := qc.ConnectionState().TLS.VerifiedChains
	if len(vcs) == 0 {
		panic(fmt.Errorf(
			"IMPOSSIBLE: no verified chains after dialing remote host %q",
			addr,
		))
	}
	if len(vcs) > 1 {
		panic(fmt.Errorf(
			"TODO: handle multiple verified chains; dialing %q resulted in chains: %#v",
			addr, vcs,
		))
	}

	vc := vcs[0]
	ca := vc[len(vc)-1]

	notify := d.CAPool.NotifyRemoval(ca)
	if notify == nil {
		panic(errors.New(
			"BUG: failed to get notify removal channel after successful connection to peer",
		))
	}

	// TODO: start a new goroutine for a context.WithCancelCause paired with notify.

	// ---- end of code copied from (*Node).DialAndJoin

	res, err := d.bootstrapNeighbor(ctx, qc)
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
	pResp := make(chan dk.NewPeeringResponse, 1)
	req := dk.NewPeeringRequest{
		QuicConn: qc,

		AdmissionStream:  res.Admission,
		DisconnectStream: res.Disconnect,
		ShuffleStream:    res.Shuffle,

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
			if err := qc.CloseWithError(1, "TODO: peering rejected: "+resp.RejectReason); err != nil {
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
) (dbsneighbor.Result, error) {
	p := dbsneighbor.Protocol{
		Log:  d.Log.With("protocol", "outgoing_bootstrap_neighbor"),
		Conn: qc,
		Cfg: dbsneighbor.Config{
			NowFn: time.Now,
		},
	}

	res, err := p.Run(ctx)
	if err != nil {
		return res, fmt.Errorf("bootstrap by neighbor message failed: %w", err)
	}

	return res, nil
}
