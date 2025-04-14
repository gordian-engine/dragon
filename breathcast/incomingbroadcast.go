package breathcast

import "log/slog"

// incomingBroadcast manages the incoming broadcast from a peer.
// The remote may or may not have the entire data set,
// but at a minimum they have the application header.
type incomingBroadcast struct {
	log *slog.Logger

	op *BroadcastOperation

	// Store the state separately from the BroadcastOperation,
	// so that the main operation can clear its incomingState
	// when no longer needed,
	// without causing a data race on in-flight incoming broadcasts.
	state *incomingState
}
