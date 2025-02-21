// Package dbsan contains the types for handling protocol bootstrap,
// specifically to accept a neighbor message.
//
// The bootstrapping flow for accepting a neighbor message looks like:
//   - Wait for a neighbor message
//   - Send a reply that denies the request and then disconnect, or:
//   - Send a reply that acknowledges the request
//   - Wait for the peer to create disconnect and shuffle streams
//   - Bootstrapping is complete
package dbsan
