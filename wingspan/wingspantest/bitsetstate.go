package wingspantest

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

	updates    chan bitsetUpdate
	newRemotes chan (chan<- newRemoteResult)

	done chan struct{}
}

type bitsetUpdate struct {
	U    uint32
	Resp chan struct{}
}

type newRemoteResult struct {
	Remote *RemoteBitsetState
	M      *dchan.Multicast[uint32]
}

func NewCentralBitsetState(
	ctx context.Context, sz uint,
) (*CentralBitsetState, *dchan.Multicast[uint32]) {
	bs := bitset.MustNew(sz)
	m := dchan.NewMulticast[uint32]()
	s := &CentralBitsetState{
		bs: bs,
		m:  m,

		updates:    make(chan bitsetUpdate),
		newRemotes: make(chan (chan<- newRemoteResult)),

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

		case req := <-s.newRemotes:
			res := newRemoteResult{
				Remote: newRemoteBitsetState(s.bs),
				M:      s.m,
			}
			// Unbuffered so we don't need to select.
			req <- res
		}
	}
}

func (s *CentralBitsetState) Wait() {
	<-s.done
}

func (s *CentralBitsetState) UpdateFromRemote(ctx context.Context, d uint32) error {
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

func (s *CentralBitsetState) NewRemoteState(ctx context.Context) (
	wspacket.RemoteState[uint32], *dchan.Multicast[uint32], error,
) {
	ch := make(chan newRemoteResult, 1)
	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case s.newRemotes <- ch:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case res := <-ch:
		return res.Remote, res.M, nil
	}
}

type RemoteBitsetState struct {
	have, sent *bitset.BitSet
}

func newRemoteBitsetState(initial *bitset.BitSet) *RemoteBitsetState {
	sent := bitset.MustNew(initial.Len())
	return &RemoteBitsetState{
		have: initial,
		sent: sent,
	}
}

func (s *RemoteBitsetState) ApplyUpdateFromLocal(d uint32) error {
	s.have.Set(uint(d))
	return nil
}

func (s *RemoteBitsetState) ApplyUpdateFromRemote(d uint32) error {
	s.have.Set(uint(d))
	return nil
}

func (s *RemoteBitsetState) UnsentPackets() iter.Seq[wspacket.Packet] {
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

type bitsetPacket struct {
	b     uint32
	owner *RemoteBitsetState
}

func (p bitsetPacket) Bytes() []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], p.b)
	return buf[:]
}

func (p bitsetPacket) MarkSent() {
	p.owner.sent.Set(uint(p.b))
}
