# DRAGON

DRAGON stands for Decentralized Routing Across Generic Overlay Network.
It implements a peer-to-peer mesh network.
Consumers have access to the connections between peers,
receiving notifications as connections are established with new peers
or as peers disconnect from our node.
Consumers are currently expected to develop their own custom messaging primitives;
DRAGON automatically handles peer membership and connectivity.

DRAGON was written for use in the
[Gordian](https://github.com/gordian-engine/gordian/") consensus engine,
but it should be usable in almost any project that needs a p2p mesh network.

Therefore, our initial goals are to implement specific messaging patterns
directly in the Gordian project first.
As we have success with applying those patterns,
we will figure out how to expose new primitives in DRAGON
to reduce the required boilerplate for other applications.

## Implementation details

DRAGON is built on [HyParView](https://asc.di.fct.unl.pt/~jleitao/pdf/dsn07-leitao.pdf).
It follows all the standard HyParView messages.

### Modularity

DRAGON is modular and lets you provide custom implementations
for some core parts of the HyParView stack.

For example, you can provide a
[`dview.Manager`](https://pkg.go.dev/github.com/gordian-engine/dragon/dview#Manager)
to make application-specific decisions about managing
your active and passive peers.
(We provide
[`dviewrand.Manager`](https://pkg.go.dev/github.com/gordian-engine/dragon/dview/dviewrand#Manager)
to make random decisions, closely following the behavior
detailed in the whitepaper.)

We have plans to experiment with a view manager that uses
geographic IP lookup to enforce geographic diversity of peers,
while simultaneously applying some preference of geographically close peers.

You can control how often your node initiates shuffles through the
[`dragon.NodeConfig.ShuffleSignal`](https://pkg.go.dev/github.com/gordian-engine/dragon/#NodeConfig)
channel.

### Divergence from the HyParView whitepaper

One distinction from plain HyParView is
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

DRAGON uses [QUIC](https://quicwg.org/) for the transport layer
(implemented with the [quic-go](https://github.com/quic-go/quic-go) project).
The key features of QUIC that led to deciding its use as the transport layer are:

- Built-in TLS support, so we can enforce authentication of every peer in the network
- Native support for multiplexing many streams over a single connection,
  so that no single stream of data directly blocks sending or receiving another stream
- The ability to send unreliable datagrams,
  which allows for some very specific cases of optimistic data transfers

In QUIC, clean disconnects are accompanied with
a numeric exit code and a textual reason; 
therefore we use QUIC disconnects in place of a standalone "disconnect" message.
