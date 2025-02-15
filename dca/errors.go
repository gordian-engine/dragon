package dca

import "errors"

// ErrCertRemoved is returned when a live connection to a peer
// is interrupted due to the peer's CA being removed from the trusted peers.
var ErrCertRemoved = errors.New("certificate removed from trusted set")
