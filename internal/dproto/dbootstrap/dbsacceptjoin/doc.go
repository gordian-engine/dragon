// Package dbsacceptjoin contains the types for handling protocol bootstrap,
// specifically to accept a join message.
//
// In bootstrapping the protocol, the joining node is the node
// who initiates a connection to the contact node.
//
// For the contact node, the bootstrapping flow for a Join message looks like:
//   - Wait for, and then read, a Join message
//   - Validate the Join message
//   - If Join message is acceptable, send a Neigbbor message (otherwise disconnect)
//   - Wait for NeighborReply message
//   - Create disconnect and shuffle stream
//   - Bootstrapping is complete
package dbsacceptjoin
