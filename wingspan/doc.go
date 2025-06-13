// Package wingspan contains the "wingspan" protocol,
// providing an epidemic-style gossip
// where the application controls "facts"
// that need to propagate through the network.
// Any participant may originate a fact,
// and the application layer is expected to validate incoming facts.
//
// The protocol provides support for simple, disjoint fact sets
// and also for dynamic fact sets where new facts may supersede
// a subset of earlier facts.
package wingspan
