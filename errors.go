package dragon

// AlreadyConnectedToNodeError is returned from [*Node.DialAndJoin]
// if the given address is already connected to the current node.
type AlreadyConnectedToNodeError struct {
	Addr string
}

func (e AlreadyConnectedToNodeError) Error() string {
	return "already connected to node " + e.Addr
}
