package wspackettest

import (
	"context"
	"encoding/binary"
	"iter"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
)

// CentralBitsetState implements [wspacket.CentralState[uint32]].
type CentralBitsetState struct {
	bs *bitset.BitSet

	m *dchan.Multicast[uint32]

	updates      chan bitsetUpdate
	newOutbounds chan (chan<- newOutboundStateResult)
	newInbounds  chan (chan<- newInboundStateResult)

	done chan struct{}
}

type bitsetUpdate struct {
	U    uint32
	Resp chan struct{}
}

type newOutboundStateResult struct {
	State *OutboundBitsetState
	M     *dchan.Multicast[uint32]
}

type newInboundStateResult struct {
	State *InboundBitsetState
	M     *dchan.Multicast[uint32]
}

func NewCentralBitsetState(
	ctx context.Context, sz uint,
) (*CentralBitsetState, *dchan.Multicast[uint32]) {
	bs := bitset.MustNew(sz)
	m := dchan.NewMulticast[uint32]()
	s := &CentralBitsetState{
		bs: bs,
		m:  m,

		updates:      make(chan bitsetUpdate),
		newOutbounds: make(chan (chan<- newOutboundStateResult)),
		newInbounds:  make(chan (chan<- newInboundStateResult)),

		done: make(chan struct{}),
	}
	go s.mainLoop(ctx)

	return s, m
}

func (s *CentralBitsetState) mainLoop(ctx context.Context) {
	defer close(s.done)

	for {
		select {
		case <-ctx.Done():
			return
		case u := <-s.updates:
			s.bs.Set(uint(u.U))
			close(u.Resp)

			s.m.Set(u.U)
			s.m = s.m.Next

		case req := <-s.newOutbounds:
			res := newOutboundStateResult{
				State: newRemoteBitsetState(s.bs),
				M:     s.m,
			}
			// Unbuffered so we don't need to select.
			req <- res

		case req := <-s.newInbounds:
			res := newInboundStateResult{
				State: newInboundBitsetState(s.bs),
				M:     s.m,
			}
			// Unbuffered so we don't need to select.
			req <- res
		}
	}
}

func (s *CentralBitsetState) Wait() {
	<-s.done
}

func (s *CentralBitsetState) UpdateFromPeer(ctx context.Context, d uint32) error {
	resp := make(chan struct{})
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case s.updates <- bitsetUpdate{
		U:    d,
		Resp: resp,
	}: // Okay
	}

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-resp:
		return nil
	}
}

func (s *CentralBitsetState) NewOutboundRemoteState(ctx context.Context) (
	wspacket.OutboundRemoteState[uint32], *dchan.Multicast[uint32], error,
) {
	ch := make(chan newOutboundStateResult, 1)
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

func (s *CentralBitsetState) NewInboundRemoteState(ctx context.Context) (
	wspacket.InboundRemoteState[uint32], *dchan.Multicast[uint32], error,
) {
	ch := make(chan newInboundStateResult, 1)
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

// OutboundBitsetState is an implementation of [wspacket.OutboundRemoteState]
// for [CentralBitsetState].
type OutboundBitsetState struct {
	have, sent *bitset.BitSet
}

func newRemoteBitsetState(initial *bitset.BitSet) *OutboundBitsetState {
	sent := bitset.MustNew(initial.Len())
	return &OutboundBitsetState{
		have: initial,
		sent: sent,
	}
}

func (s *OutboundBitsetState) ApplyUpdateFromCentral(d uint32) error {
	s.have.Set(uint(d))
	return nil
}

func (s *OutboundBitsetState) ApplyUpdateFromPeer(d uint32) error {
	s.have.Set(uint(d))
	return nil
}

func (s *OutboundBitsetState) UnsentPackets() iter.Seq[wspacket.Packet] {
	p := bitsetPacket{owner: s}
	return func(yield func(wspacket.Packet) bool) {
		// Slightly inefficient to create a new bitset each time here,
		// but this is only for tests anyway.
		choose := s.have.Difference(s.sent)

		for u, ok := choose.NextSet(0); ok; u, ok = choose.NextSet(u + 1) {
			p.b = uint32(u)
			if !yield(p) {
				return
			}
		}
	}
}

// InboundBitsetState is an implementation of [wspacket.InboundRemoteState]
// for [CentralBitsetState].
type InboundBitsetState struct {
	have    *bitset.BitSet
	checked *bitset.BitSet
}

func newInboundBitsetState(initial *bitset.BitSet) *InboundBitsetState {
	return &InboundBitsetState{
		have:    initial,
		checked: bitset.MustNew(initial.Len()),
	}
}

func (s *InboundBitsetState) ApplyUpdateFromCentral(d uint32) error {
	// TODO: bounds check.
	s.have.Set(uint(d))
	return nil
}

func (s *InboundBitsetState) ApplyUpdateFromPeer(d uint32) error {
	// TODO: bounds check.
	s.have.Set(uint(d))
	s.checked.Set(uint(d))
	return nil
}

func (s *InboundBitsetState) CheckIncoming(d uint32) error {
	if s.checked.Test(uint(d)) {
		return wspacket.ErrDuplicateSentPacket
	}

	if s.have.Test(uint(d)) {
		return wspacket.ErrAlreadyHavePacket
	}

	// TODO: bounds check.

	return nil
}

type bitsetPacket struct {
	b     uint32
	owner *OutboundBitsetState
}

func (p bitsetPacket) Bytes() []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], p.b)
	return buf[:]
}

func (p bitsetPacket) MarkSent() {
	p.owner.sent.Set(uint(p.b))
}
