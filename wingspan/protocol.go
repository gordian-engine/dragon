package wingspan

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"sync"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/gordian-engine/dragon/wingspan/internal/wsi"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
)

// Protocol controls all the operations of the "wingspan" protocol.
//
// The key method on Protocol is [*Protocol.NewSession].
// A "session" has a session ID and is the agreed "topic"
// for gossip among the network.
type Protocol[D any] struct {
	log *slog.Logger

	// Multicast for connection changes,
	// so that broadcast operations can observe it directly.
	connChanges *dchan.Multicast[dconn.Change]

	startSessionRequests chan sessionRequest[D]

	// Application-decided protocol ID.
	// Necessary for outgoing streams.
	protocolID byte

	// All sessions within a protocol instance
	// must have the same length,
	// so that they can be uniformly decoded.
	sessionIDLength uint8

	// Separate from the wait group,
	// to avoid possible race condition when closing.
	mainLoopDone chan struct{}

	// Tracks the sessions in progress.
	wg sync.WaitGroup
}

// sessionRequest contains the details necessary to run a session.
// The main loop starts the goroutine for the session
// and sends a Session on the response channel,
// so that [*Protocol.NewSession] can return a cancelable session.
type sessionRequest[D any] struct {
	Session *wsi.Session[D]

	ParsePacketFn func(io.Reader) (D, error)

	Resp chan Session[D]
}

// ProtocolConfig is the configuration passed to [NewProtocol].
type ProtocolConfig struct {
	// The initial connections to use.
	// The protocol will own this slice,
	// so the caller must not retain any references to it.
	InitialConnections []dconn.Conn

	// How to inform the protocol of connection changes.
	// Using dchan.Multicast for this reduces the number of required goroutines,
	// at the cost of a heap-allocated linked list.
	ConnectionChanges *dchan.Multicast[dconn.Change]

	// The single protocol-identifying byte to be sent on outgoing streams.
	ProtocolID byte

	// The fixed length of session identifiers.
	SessionIDLength uint8
}

func NewProtocol[D any](
	ctx context.Context,
	log *slog.Logger,
	cfg ProtocolConfig,
) *Protocol[D] {
	if cfg.SessionIDLength == 0 {
		// It's plausible that there would be a use case
		// for saving the space required for session IDs,
		// so for now we will allow zero with a warning.
		log.Warn(
			"Using session ID length of zero prevents the network from having more than one distinct session at a time",
		)
	}

	p := &Protocol[D]{
		log: log,

		connChanges: cfg.ConnectionChanges,

		startSessionRequests: make(chan sessionRequest[D]),

		protocolID: cfg.ProtocolID,

		sessionIDLength: cfg.SessionIDLength,

		mainLoopDone: make(chan struct{}),
	}

	conns := make(map[dcert.LeafCertHandle]dconn.Conn, len(cfg.InitialConnections))
	for _, c := range cfg.InitialConnections {
		conns[c.Chain.LeafHandle] = c
	}

	go p.mainLoop(ctx, conns)

	return p
}

func (p *Protocol[D]) mainLoop(ctx context.Context, conns map[dcert.LeafCertHandle]dconn.Conn) {
	defer close(p.mainLoopDone)

	for {
		select {
		case <-ctx.Done():
			p.log.Info(
				"Stopping due to context cancellation",
				"cause", context.Cause(ctx),
			)
			return

		case req := <-p.startSessionRequests:
			p.handleStartSessionRequest(ctx, req, conns)

		case <-p.connChanges.Ready:
			cc := p.connChanges.Val
			p.connChanges = p.connChanges.Next
			if cc.Adding {
				conns[cc.Conn.Chain.LeafHandle] = cc.Conn
			} else {
				delete(conns, cc.Conn.Chain.LeafHandle)
			}
		}
	}
}

func (p *Protocol[D]) Wait() {
	<-p.mainLoopDone
	p.wg.Wait()
}

func (p *Protocol[D]) handleStartSessionRequest(
	ctx context.Context,
	req sessionRequest[D],
	conns map[dcert.LeafCertHandle]dconn.Conn,
) {
	ctx, cancel := context.WithCancelCause(ctx)

	p.wg.Add(1)
	go req.Session.Run(
		ctx, &p.wg,
		req.ParsePacketFn,
		maps.Clone(conns),
		p.connChanges,
	)

	// Response channel is buffered.
	req.Resp <- Session[D]{
		s:      req.Session,
		cancel: cancel,
	}
}

// NewSession creates a new session with the given session ID
// and application header, associating it with p.
//
// The parsePacketFn callback is used to read a packet
// from the peer's network stream and convert it into a D value.
// The function will be called concurrently.
func (p *Protocol[D]) NewSession(
	ctx context.Context,
	id []byte,
	appHeader []byte,
	state wspacket.CentralState[D],
	deltas *dchan.Multicast[D],
	parsePacketFn func(io.Reader) (D, error),
) (Session[D], error) {
	if len(id) != int(p.sessionIDLength) {
		return Session[D]{}, fmt.Errorf(
			"BUG: attempted to create session with invalid ID length %d (must be %d)",
			len(id), p.sessionIDLength,
		)
	}

	s := wsi.NewSession(
		p.log.With("sid", fmt.Sprintf("%x", id)), // TODO: hex log helper.
		p.protocolID, id, appHeader,
		state, deltas,
	)

	resp := make(chan Session[D], 1)
	select {
	case <-ctx.Done():
		return Session[D]{}, fmt.Errorf(
			"context canceled while making request to start session: %w",
			context.Cause(ctx),
		)
	case p.startSessionRequests <- sessionRequest[D]{
		Session:       s,
		ParsePacketFn: parsePacketFn,
		Resp:          resp,
	}:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return Session[D]{}, fmt.Errorf(
			"context canceled while waiting for response to start session: %w",
			context.Cause(ctx),
		)
	case h := <-resp:
		return h, nil
	}
}

// ExtractStreamSessionID extracts the session ID
// from the given reader (which should be a [quic.ReceiveStream]).
// The extracted data is appended to the given dst slice,
// which is permitted to be nil.
//
// The caller is responsible for setting any read deadlines
// prior to calling the method.
//
// It is assumed that the caller has already consumed
// the protocol ID byte matching [ProtocolConfig.ProtocolID].
func (p *Protocol[D]) ExtractStreamSessionID(
	r io.Reader, dst []byte,
) ([]byte, error) {
	if cap(dst) >= int(p.sessionIDLength) {
		dst = dst[:p.sessionIDLength]
	} else {
		dst = make([]byte, p.sessionIDLength)
	}

	if _, err := io.ReadFull(r, dst); err != nil {
		return dst, fmt.Errorf(
			"failed to read session ID from incoming stream: %w",
			err,
		)
	}

	return dst, nil
}

// ExtractStreamApplicationHeader extracts the application-provided header data
// from the given reader (which should be a QUIC stream).
// The extracted data is appended to the given dst slice,
// which is permitted to be nil.
//
// The caller is responsible for setting any read deadlines
// prior to calling the method.
//
// It is assumed that the caller has already consumed both
// the protocol ID byte matching [ProtocolConfig.ProtocolID],
// and the session ID via [*Protocol.ExtractStreamSessionID].
func ExtractStreamApplicationHeader(
	r io.Reader, dst []byte,
) ([]byte, error) {
	// Attempt to right-size the destination.
	// It's hard to predict how big the application header would be,
	// and we don't really want to oversize or undersize it,
	// so make a dedicated size buffer if needed.
	var szBuf []byte
	if cap(dst) >= 2 {
		szBuf = dst[:2]
	} else {
		szBuf = make([]byte, 2)
	}

	if _, err := io.ReadFull(r, szBuf); err != nil {
		return dst, fmt.Errorf(
			"failed to read application header size from incoming stream: %w",
			err,
		)
	}

	sz := binary.BigEndian.Uint16(szBuf)

	if cap(dst) >= int(sz) {
		dst = dst[:sz]
	} else {
		dst = make([]byte, sz)
	}

	if _, err := io.ReadFull(r, dst); err != nil {
		return dst, fmt.Errorf(
			"failed to read session ID from incoming stream: %w",
			err,
		)
	}

	return dst, nil
}
