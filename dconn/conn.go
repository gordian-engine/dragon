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
	// the first byte written must be >= 128.
	// This is so that dragon internals can route accepted streams
	// to the application layer correctly.
	//
	// Consumers must be aware that this connection
	// is shared with dragon internal protocol management.
	QUIC quic.Connection

	// Chain is the certificate chain of the peer.
	Chain dcert.Chain

	// TODO: we probably need at least one additional field,
	// giving the view manager an opportunity to
	// set application-specific metadata on the connection.
}
