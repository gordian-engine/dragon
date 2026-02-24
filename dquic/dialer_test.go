package dquic_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/dquic/dquictest"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestDialer_ClosesConnUponCARemoval(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	ls := dquictest.NewListenerSet(t, ctx, 2)

	d0 := ls.Dialer(0)
	// Make sure the dialer has an independent pool,
	// so nothing that happens to the remote's pool
	// can affect the dialer's pool.
	d0.CAPool = dcert.NewPoolFromCerts(
		[]*x509.Certificate{ls.CAs[1].Cert},
	)

	listenErrCh := make(chan error, 1)
	var listenConn *quic.Conn
	go func() {
		conn, err := ls.QLs[1].Accept(ctx)
		if err != nil {
			listenErrCh <- err
			return
		}
		listenConn = conn
		listenErrCh <- nil
	}()

	res, err := d0.Dial(ctx, ls.UDPConns[1].LocalAddr())
	require.NoError(t, err)
	dialerConn := res.Conn

	select {
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for strema accept")
	case err := <-listenErrCh:
		require.NoError(t, err)
	}

	// There is an established connection,
	// and now if the dialer's pool removes the peer certificate,
	// the connection is closed (by a background goroutine
	// that was created during the call to Dial).
	d0.CAPool.RemoveCA(ls.CAs[1].Cert)

	// Time to allow other goroutine to process removal.
	time.Sleep(10 * time.Millisecond)

	// We don't see any immediate sign that the connection was closed;
	// we have to use the connection to observe it.
	_, err = dialerConn.OpenStreamSync(ctx)
	var appErr *quic.ApplicationError
	require.ErrorAs(t, err, &appErr)
	require.Equal(t, appErr, &quic.ApplicationError{
		Remote:       false,
		ErrorCode:    quic.ApplicationErrorCode(dquic.CARemoved),
		ErrorMessage: dquic.CARemovedMessage,
	})

	// Correpsonding error observed on the remote.
	_, err = listenConn.OpenStreamSync(ctx)
	require.ErrorAs(t, err, &appErr)
	require.Equal(t, appErr, &quic.ApplicationError{
		Remote:       true,
		ErrorCode:    quic.ApplicationErrorCode(dquic.CARemoved),
		ErrorMessage: dquic.CARemovedMessage,
	})
}
