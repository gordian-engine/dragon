// Package dbsneighbor contains the types for handling protocol bootstrap,
// specifically to send a neighbor message to a candidate node.
//
// In this case, we use the term "candidate node" because
// we do not need to distinguish between a node who originated a join message
// and a node who was in our passive view.
package dbsneighbor
