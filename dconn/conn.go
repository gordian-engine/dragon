package dconn

import (
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dquic"
)

// Conn is a live connection to another peer in the dragon network.
type Conn struct {
	// The QUIC connection to the peer.
	//
	// Consumers must be aware that this connection
	// is shared with dragon internal protocol management.
	//
	// In particular, when opening a new bidirectional stream,
	// the first byte written must be >= [MinAppProtocolID].
	// This is so that dragon internals can route accepted streams
	// to the application layer correctly.
	QUIC dquic.Conn

	// Chain is the certificate chain of the peer.
	Chain dcert.Chain

	// TODO: we probably need at least one additional field,
	// giving the view manager an opportunity to
	// set application-specific metadata on the connection.
}

// Change is the value meant to be sent on a channel
// indicating newly added or removed connections.
type Change struct {
	// The connection involved in the change.
	Conn Conn

	// If true, the connection has been added to the view set.
	// Otherwise, the connection is being removed.
	Adding bool
}

// The first byte sent on a new stream is the "protocol ID".
// This value is the lowest allowed byte
// to ensure that the stream is routed to the application layer
// through the Conn type.
const MinAppProtocolID byte = 128
