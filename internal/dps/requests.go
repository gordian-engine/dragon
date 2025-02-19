package dps

// addRequest is a request to add a peer to the active peer set.
type addRequest struct {
	IPeer iPeer

	// No detail necessary in acknowledgement.
	Resp chan struct{}
}

type removeRequest struct {
	PCI PeerCertID

	// No detail necessary in acknowledgement.
	Resp chan struct{}
}
