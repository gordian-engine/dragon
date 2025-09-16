package wspackettest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"

	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
)

var errInvalidSignature = errors.New("invalid signature")

type rawEdKey [ed25519.PublicKeySize]byte

// Ed25519State implements [wspacket.CentralState].
// This is a simplified implementation intended only for use in tests.
// Do not use this in production code.
type Ed25519State struct {
	m *dpubsub.Stream[Ed25519Delta]

	signContent []byte

	// Stringified public key to signature bytes.
	sigs map[string][]byte

	updatesFromPeers chan verifiedEd25519SignatureRequest
	newOutbounds     chan (chan<- newOutboundEd25519StateResult)
	newInbounds      chan (chan<- newInboundEd25519StateResult)

	done chan struct{}
}

var _ wspacket.CentralState[Ed25519PacketIn, Ed25519PacketOut, Ed25519Delta, Ed25519Delta] = (*Ed25519State)(nil)

// Ed25519Delta implements the D type parameter
// expected throughout the wspacket stack.
type Ed25519Delta struct {
	PubKey ed25519.PublicKey
	Sig    []byte
}

type verifiedEd25519SignatureRequest struct {
	StringKey string
	Delta     Ed25519Delta
	Resp      chan error
}

type newOutboundEd25519StateResult struct {
	State *ed25519OutboundState
	M     *dpubsub.Stream[Ed25519Delta]
}

type newInboundEd25519StateResult struct {
	State *ed25519InboundState
	M     *dpubsub.Stream[Ed25519Delta]
}

// NewEd25519State returns a new instance of Ed25519State.
// The ctx argument controls †he lifecycle of the state.
// The signContent argument is used to verify signatures.
// The allowedKeys argument is the order-insensitive list
// of keys who may provide signatures in this state.
func NewEd25519State(
	ctx context.Context,
	signContent []byte,
	allowedKeys []ed25519.PublicKey,
) (*Ed25519State, *dpubsub.Stream[Ed25519Delta]) {
	m := dpubsub.NewStream[Ed25519Delta]()
	s := &Ed25519State{
		m: m,

		signContent: signContent,

		sigs: make(map[string][]byte, len(allowedKeys)),

		// Unbuffered since caller blocks.
		updatesFromPeers: make(chan verifiedEd25519SignatureRequest),
		newOutbounds:     make(chan (chan<- newOutboundEd25519StateResult)),
		newInbounds:      make(chan (chan<- newInboundEd25519StateResult)),

		done: make(chan struct{}),
	}
	for _, k := range allowedKeys {
		// Initialize every key in the map
		// so we have a canonical list of allowed keys.
		s.sigs[string(k)] = nil
	}

	go s.mainLoop(ctx)

	return s, m
}

func (s *Ed25519State) mainLoop(ctx context.Context) {
	defer close(s.done)

	for {
		select {
		case <-ctx.Done():
			return

		case req := <-s.updatesFromPeers:
			s.handleUpdateFromPeer(req)

		case req := <-s.newOutbounds:
			peerHas := make(map[string]bool, len(s.sigs))
			for k := range s.sigs {
				peerHas[k] = false
			}
			req <- newOutboundEd25519StateResult{
				State: &ed25519OutboundState{
					sigs:    maps.Clone(s.sigs),
					peerHas: peerHas,

					peerUnverified: make(map[string][]byte, 4), // Arbitrary size.
				},
				M: s.m,
			}

		case req := <-s.newInbounds:
			req <- newInboundEd25519StateResult{
				State: &ed25519InboundState{
					have:    maps.Clone(s.sigs),
					checked: make(map[string]bool, len(s.sigs)),
				},
				M: s.m,
			}
		}
	}
}

func (s *Ed25519State) Wait() {
	<-s.done
}

func (s *Ed25519State) UpdateFromPeer(
	ctx context.Context, d Ed25519Delta,
) error {
	if !ed25519.Verify(d.PubKey, s.signContent, d.Sig) {
		return errInvalidSignature
	}

	// Send verified signature to main loop to update sigs map.
	req := verifiedEd25519SignatureRequest{
		StringKey: string(d.PubKey),
		Delta:     d,
		Resp:      make(chan error, 1),
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while sending signature to central state: %w",
			context.Cause(ctx),
		)

	case s.updatesFromPeers <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while waiting for signature response: %w",
			context.Cause(ctx),
		)

	case err := <-req.Resp:
		// Don't re-wrap error in any case.
		return err
	}
}

func (s *Ed25519State) handleUpdateFromPeer(
	req verifiedEd25519SignatureRequest,
) {
	have := s.sigs[req.StringKey]
	if have != nil {
		if !bytes.Equal(have, req.Delta.Sig) {
			// Had a verified signature that didn't match this one.
			req.Resp <- errInvalidSignature
			return
		}

		// Incoming signature matched already verified.
		req.Resp <- wspacket.ErrRedundantUpdate
		return
	}

	s.sigs[req.StringKey] = req.Delta.Sig
	req.Resp <- nil

	s.m.Publish(req.Delta)
	s.m = s.m.Next
}

func (s *Ed25519State) NewOutboundRemoteState(ctx context.Context) (
	wspacket.OutboundRemoteState[Ed25519PacketIn, Ed25519PacketOut, Ed25519Delta, Ed25519Delta],
	*dpubsub.Stream[Ed25519Delta],
	error,
) {
	ch := make(chan newOutboundEd25519StateResult, 1)

	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case s.newOutbounds <- ch:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case res := <-ch:
		return res.State, res.M, nil
	}
}

func (s *Ed25519State) NewInboundRemoteState(ctx context.Context) (
	wspacket.InboundRemoteState[Ed25519PacketIn, Ed25519Delta, Ed25519Delta],
	*dpubsub.Stream[Ed25519Delta],
	error,
) {
	ch := make(chan newInboundEd25519StateResult, 1)
	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case s.newInbounds <- ch:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case res := <-ch:
		return res.State, res.M, nil
	}
}

type ed25519OutboundState struct {
	sigs    map[string][]byte
	peerHas map[string]bool

	peerUnverified map[string][]byte
}

func (s *ed25519OutboundState) ApplyUpdateFromCentral(d Ed25519Delta) error {
	s.sigs[string(d.PubKey)] = d.Sig
	if bytes.Equal(s.peerUnverified[string(d.PubKey)], d.Sig) {
		s.peerHas[string(d.PubKey)] = true
		delete(s.peerUnverified, string(d.PubKey))
	}
	return nil
}

func (s *ed25519OutboundState) AddUnverifiedFromPeer(d Ed25519Delta) error {
	if bytes.Equal(s.sigs[string(d.PubKey)], d.Sig) {
		// Call arrived late. Nothing to do.
		return nil
	}

	// We didn't have an existing signature for this,
	// so add it to the unverified map.
	s.peerUnverified[string(d.PubKey)] = d.Sig
	return nil
}

func (s *ed25519OutboundState) UnsentPackets() iter.Seq[Ed25519PacketOut] {
	p := Ed25519PacketOut{owner: s}
	return func(yield func(Ed25519PacketOut) bool) {
		for k, has := range s.peerHas {
			if has {
				continue
			}

			sig := s.sigs[k]
			if sig == nil {
				continue
			}

			// Now, we have the signature and we don't think the peer has it.
			p.setBytes(k, sig)
			if !yield(p) {
				return
			}
		}
	}
}

type Ed25519PacketOut struct {
	owner *ed25519OutboundState
	buf   []byte
	key   string
}

func (p *Ed25519PacketOut) setBytes(key string, sig []byte) {
	var b []byte
	if cap(p.buf) >= len(key)+len(sig) {
		b = p.buf[:len(key)+len(sig)]
	} else {
		b = make([]byte, len(key)+len(sig))
	}

	copy(b, key)
	copy(b[len(key):], sig)
	p.buf = b

	p.key = key
}

func (p Ed25519PacketOut) Bytes() []byte {
	return p.buf
}

func (p Ed25519PacketOut) MarkSent() {
	p.owner.peerHas[p.key] = true
}

type Ed25519PacketIn struct {
	key []byte
	sig []byte
}

func NewEd25519PacketInForTest(key, sig []byte) Ed25519PacketIn {
	return Ed25519PacketIn{key: key, sig: sig}
}

type ed25519InboundState struct {
	have    map[string][]byte
	checked map[string]bool
}

func (s *ed25519InboundState) ApplyUpdateFromCentral(d Ed25519Delta) error {
	s.have[string(d.PubKey)] = d.Sig
	return nil
}

func (s *ed25519InboundState) ApplyUpdateFromPeer(d Ed25519Delta) error {
	s.have[string(d.PubKey)] = d.Sig
	s.checked[string(d.PubKey)] = true
	return nil
}

func (s *ed25519InboundState) CheckIncoming(p Ed25519PacketIn) error {
	if s.checked[string(p.key)] {
		return wspacket.ErrDuplicateSentPacket
	}

	if have := s.have[string(p.key)]; have != nil {
		return wspacket.ErrAlreadyHavePacket
	}

	s.checked[string(p.key)] = true

	return nil
}

func (s *ed25519InboundState) PacketToDelta(p Ed25519PacketIn) (Ed25519Delta, error) {
	return ParseEd25519Packet(
		io.MultiReader(
			bytes.NewReader(p.key),
			bytes.NewReader(p.sig),
		),
	)
}

func (s *ed25519InboundState) ParsePacket(r io.Reader) (Ed25519PacketIn, error) {
	pkBuf := make([]byte, ed25519.PublicKeySize)

	if _, err := io.ReadFull(r, pkBuf); err != nil {
		return Ed25519PacketIn{}, fmt.Errorf(
			"failed to read public key: %w", err,
		)
	}

	sigBuf := make([]byte, ed25519.SignatureSize)
	if _, err := io.ReadFull(r, sigBuf); err != nil {
		return Ed25519PacketIn{}, fmt.Errorf(
			"failed to read signature: %w", err,
		)
	}

	return Ed25519PacketIn{
		key: pkBuf,
		sig: sigBuf,
	}, nil
}

// ParseEd25519Packet is the packet parsing function
// intended to be passed to [*wspacket.Protocol.NewSession].
func ParseEd25519Packet(r io.Reader) (Ed25519Delta, error) {
	var d Ed25519Delta

	pkBuf := make([]byte, ed25519.PublicKeySize)

	if _, err := io.ReadFull(r, pkBuf); err != nil {
		return d, fmt.Errorf(
			"failed to read public key: %w", err,
		)
	}

	sigBuf := make([]byte, ed25519.SignatureSize)
	if _, err := io.ReadFull(r, sigBuf); err != nil {
		return d, fmt.Errorf(
			"failed to read signature: %w", err,
		)
	}

	d.PubKey = ed25519.PublicKey(pkBuf)
	d.Sig = sigBuf
	return d, nil
}
