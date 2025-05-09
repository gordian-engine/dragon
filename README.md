# DRAGON

DRAGON stands for Decentralized Routing Across Generic Overlay Network.
It implements a peer-to-peer mesh network.
Consumers have access to the connections between peers,
receiving notifications as connections are established with new peers
or as peers disconnect from our node.
Consumers are currently expected to develop their own custom messaging primitives;
DRAGON automatically handles peer membership and connectivity.

DRAGON was written for use in the
[Gordian](https://github.com/gordian-engine/gordian/) consensus engine,
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

### Protocols included

#### breathcast

See the [`breathcast` package](https://pkg.go.dev/github.com/gordian-engine/dragon/breathcast)
for a custom broadcast protocol.

One node on the network provides an arbitrary set of data
and some details on how it is to be transfered, to create an "origination".
The origination includes an [erasure-coding](https://en.wikipedia.org/wiki/Erasure_code) of the input data
The erasure-coded shards also include corresponding Merkle proofs;
therefore, clients who have the Merkle root can verify
that they have correctly received a shard of the original data.

The broadcast originator opens a QUIC stream to its peers.
The originator sends a synchronous protocol and application header.
The receiver parses those headers to determine details about the broadcast,
such as the count of data and parity shards,
the size of each shard, and the Merkle root for the shards.
The headers also include application-specific data that must be parsed.
In Gordian for instance, the application header would include
the block height, the voting round, the block hash, and so on.

If the receiver chooses to accept the broadcast,
the receiver sends a bitset indicating which shards it already has.
Next, the originator sends unreliable datagrams for each missing shard.
Ideally, enough of those shards reach the peer successfully
such that the peer is able to fully reconstruct the data.
If the receiver does reconstruct the data, it closes the broadcast stream.
If not, the originator sends a message indicating that
the unreliable transmission has completed;
the receiver replies with an updated bitset,
and the originator sends remaining shards over the reliable stream,
allowing the receiver to reconstruct the original data.

While the originator is broadcasting the data to its immediate peers,
those receivers open connections to their own peers
in order to forward the headers and the data shards
to their own immediate peers.
As a relaying peer receives an individual data shard,
it sends that shard as an unreliable datagram to a receiving peer.
The receiving peer periodically sends bitsets to the relayer
indicating what shards it already has.
Following the unreliable transmission of a particular data shard,
if the relayer does not see its acknowledgement within two bitset updates,
the relayer falls back to sending the shard over the reliable stream.

Once a relaying peer receives enough shards to reconstruct the original data,
it acts like an originating broadcaster,
sending remaining shards over unreliable transport
and then sending anything else missed over the reliable stream.
