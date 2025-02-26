// Package dmsg contains simple types relating to messages
// and the transport layer (such as [dcert] or QUIC connections and streams).
//
// Keeping this package narrow and simple ensures it can be imported
// by [dk], [dps], and [dfanout] properly;
// and we don't have to push types into dfanout just because they are used there.
package dmsg
