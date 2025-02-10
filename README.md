# DRAGON

DRAGON stands for Decentralized Routing Across Geographic Overlay Network.

It is intended for use in the [Gordian](https://github.com/gordian-engine/gordian/") consensus engine,
but it could likely be used as a library in other situations as well.

## Implementation details

DRAGON is built on [HyParView](https://asc.di.fct.unl.pt/~jleitao/pdf/dsn07-leitao.pdf).
It follows all the standard HyParView messages.
The largest difference from "vanilla" HyParView is that DRAGON
relies on geographic IP lookup to discover approximate location of peers;
and then within the active and passive peer sets,
nodes maintain separate buckets of nearby and distant peers.
This allows preferential fast transfer to nearby peers
and network robustness with guaranteed out-of-region peers.

Another, lesser distinction from plain HyParView is
that nodes have an explicit whitelist of trusted certificate authorities.
Any incoming connection must present a client certificate
belonging to one of the trusted CAs;
and by default, one node will not connect to more than one peer
belonging to the same CA.
This allows one operating entity to maintain multiple peers in the network
but without risk of causing an overwhelming number of connections
relative to the number of CAs represented within the network.

The list of trusted CAs is expected to be a one-to-one mapping
with active validators on the blockchain that DRAGON is assisting.
A validator leaving the active set should cause all its corresponding nodes to be disconnected.
Furthermore, separating the p2p layer's encryption from validation signing
reduces the attack surface for validators' private keys.

DRAGON uses [QUIC](https://quicwg.org/) for the transport layer.
