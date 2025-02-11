package dpmsg

// The current protocol version.
// We don't support multiple versions yet,
// but we make this part of certain protocol messages
// in order to help forwards and backward compatibility.
const CurrentProtocolVersion byte = 1
