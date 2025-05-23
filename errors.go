package dragon

import "github.com/gordian-engine/dragon/dcert"

// AlreadyConnectedToAddrError is returned from [*Node.DialAndJoin]
// if the given address is already connected to the current node.
type AlreadyConnectedToAddrError struct {
	Addr string
}

func (e AlreadyConnectedToAddrError) Error() string {
	return "already connected to node by address " + e.Addr
}

type AlreadyConnectedToCertError struct {
	Chain dcert.Chain
}

func (e AlreadyConnectedToCertError) Error() string {
	_ = e.Chain // TODO: what is the right way to present this?
	return "already connected to a node with the same TLS certificate"
}
