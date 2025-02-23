// Package dbssendjoin contains the types for handling protocol bootstrap,
// specifically to send a join message to a contact node.
//
// From the joining node's perspective, the bootstrap process works like this:
//   - Send a Join message
//   - Wait for a Neighbor message (or get disconnected if contact node
//     is not going to accept our Join message)
//   - Receive Neighbor message from contact node
//   - Send Neighbor Reply message acknowledging the Neighbor message
//   - Accept two more streams: the disconnect stream and the shuffle stream
//   - The QUIC stream we used for bootstrapping is "promoted" to the Forward Join stream
//   - Bootstrapping is complete
package dbssendjoin
