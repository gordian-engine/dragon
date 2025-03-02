package dconn

import (
	"github.com/gordian-engine/dragon/dcert"
	"github.com/quic-go/quic-go"
)

// Conn is a live connection to another peer in the dragon network.
type Conn struct {
	// The QUIC connection to the peer.
	// Note that quic.Connection is an interface;
	// this connection wraps a Connection
	// originating directly from quic-go package.
	// As a result, some methods require special treatment.
	//
	// In particular, when opening a new bidirectional stream,
	// the first byte written must be >= [MinAppProtocolID].
	// This is so that dragon internals can route accepted streams
	// to the application layer correctly.
	//
	// Consumers must be aware that this connection
	// is shared with dragon internal protocol management.
	QUIC quic.Connection

	// Chain is the certificate chain of the peer.
	Chain dcert.Chain

	// This channel is closed when the connection is
	// removed from the active view.
	//
	// This does not necessarily give the application
	// a chance to do a clean shutdown on the connection,
	// although at the protocol layer a proper disconnect message
	// will be sent automatically.
	LeavingActiveView <-chan struct{}

	// TODO: we probably need at least one additional field,
	// giving the view manager an opportunity to
	// set application-specific metadata on the connection.
}

// The first byte sent on a new stream is the "protocol ID".
// This value is the lowest allowed byte
// to ensure that the stream is routed to the application layer
// through the Conn type.
const MinAppProtocolID byte = 128
