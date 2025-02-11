package dk

type JoinRequest struct {
	Resp chan JoinResponse
}

type JoinResponse struct {
	Decision JoinDecision
}

// JoinDecision informs the Node on what to do
// with a Join message.
type JoinDecision uint8

const (
	// Disconnect without forwarding.
	// Kernel is responsible for handling forward join requests.
	DisconnectJoinDecision JoinDecision = iota

	// Accept the join request,
	// by responding with a Neighbor request.
	// Kernel is responsible for handling forward join requests.
	AcceptJoinDecision
)
