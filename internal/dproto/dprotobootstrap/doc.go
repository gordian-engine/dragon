// Package dprotobootstrap contains the types for handling protocol bootstrap.
//
// In bootstrapping the protocol, the joining node is the node
// who initiates a connection to the contact node.
// From the joining node's perspective, the bootstrap process works like this:
//   - Send a Join message
//   - Wait for a Neighbor message (or get disconnected if contact node
//     is not going to accept our Join message)
//   - Receive Neighbor message from contact node
//   - Send Neighbor Reply message acknowledging the Neighbor message
//   - Accept two more streams: the disconnect stream and the shuffle stream
//   - The QUIC stream we used for bootstrapping is "promoted" to the Forward Join stream
//   - Bootstrapping is complete
//
// For the contact node, the bootstrapping flow for a Join message looks like:
//   - Wait for, and then read, a Join message
//   - Validate the Join message
//   - If Join message is acceptable, send a Neigbbor message (otherwise disconnect)
//   - Wait for NeighborReply message
//   - Create disconnect and shuffle stream
//   - Bootstrapping is complete
package dprotobootstrap
