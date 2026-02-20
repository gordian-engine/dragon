package dtrace

import (
	"fmt"
	"net"

	otelattr "go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
	otpnoop "go.opentelemetry.io/otel/trace/noop"
)

type TracerProvider = oteltrace.TracerProvider

type Tracer = oteltrace.Tracer

type KeyValueAttr = otelattr.KeyValue

// NopTracerProvider returns the otel no-op tracer provider.
// This is intended to use as a fallback when a nil tracer provider is given.
func NopTracerProvider() TracerProvider {
	return otpnoop.NewTracerProvider()
}

// WithAttributes is an alias to [oteltrace.WithAttributes]
// to allow consumers to only reference the dtrace package.
func WithAttributes(attrs ...KeyValueAttr) oteltrace.SpanStartEventOption {
	return oteltrace.WithAttributes(attrs...)
}

// LazyHexAttr returns an attribute that uses fmt.Sprintf("%x", val)
// but only evaluates the Sprintf call if the span is sampled.
func LazyHexAttr(key string, val any) KeyValueAttr {
	return otelattr.Stringer(key, lazyHex{val: val})
}

type lazyHex struct {
	val any
}

func (h lazyHex) String() string {
	return fmt.Sprintf("%x", h.val)
}

// StringerAttr returns an attribute that uses the given Stringer,
// to avoid eagerly evaluating its String method in case the span is not sampled.
func StringerAttr(key string, val fmt.Stringer) KeyValueAttr {
	return otelattr.Stringer(key, val)
}

// SpanError sets the given span to error status,
// with detail from err.Error().
func SpanError(span oteltrace.Span, err error) {
	span.SetStatus(otelcodes.Error, err.Error())
}

// ErrorAttr returns an attribute with the key "err"
// and the lazily evaluated value of err's Error() method.
func ErrorAttr(err error) KeyValueAttr {
	return otelattr.Stringer("err", errStringer{err: err})
}

type errStringer struct {
	err error
}

func (e errStringer) String() string {
	return e.err.Error()
}

type RemoteAddr interface {
	RemoteAddr() net.Addr
}

func RemoteAddrAttr(ra RemoteAddr) KeyValueAttr {
	return otelattr.Stringer("remote", lazyRemoteAddr{a: ra.RemoteAddr()})
}

type lazyRemoteAddr struct {
	a net.Addr
}

func (lra lazyRemoteAddr) String() string {
	return lra.a.String()
}

func BreathcastPacketIndexAttr(idx uint16) KeyValueAttr {
	return otelattr.Int("breathcast.packet.index", int(idx))
}
