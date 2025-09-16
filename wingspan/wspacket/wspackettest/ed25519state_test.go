package wspackettest_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/gordian-engine/dragon/wingspan/wspacket"
	"github.com/gordian-engine/dragon/wingspan/wspacket/wspackettest"
	"github.com/stretchr/testify/require"
)

func TestEd25519StateCompliance(t *testing.T) {
	t.Parallel()

	wspackettest.TestStateCompliance(t, newEd25519Fixture)
}

func newEd25519Fixture(t *testing.T, ctx context.Context, nDeltas int) (
	wspacket.CentralState[
		wspackettest.Ed25519PacketIn, wspackettest.Ed25519PacketOut,
		wspackettest.Ed25519Delta, wspackettest.Ed25519Delta,
	],
	wspackettest.StateFixture[
		wspackettest.Ed25519PacketIn,
		wspackettest.Ed25519Delta, wspackettest.Ed25519Delta,
	],
) {
	t.Helper()

	signContent := []byte(t.Name())

	pubKeys := make([]ed25519.PublicKey, nDeltas)
	privKeys := make([]ed25519.PrivateKey, nDeltas)

	for i := range nDeltas {
		pub, priv, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		pubKeys[i] = pub
		privKeys[i] = priv
	}

	dc := ed25519DeltaCreator{
		SignContent: signContent,
		PubKeys:     pubKeys,
		PrivKeys:    privKeys,
		Sigs:        make([][]byte, nDeltas),
	}

	s, _ := wspackettest.NewEd25519State(ctx, signContent, pubKeys)
	t.Cleanup(s.Wait)

	return s, &dc
}

type ed25519DeltaCreator struct {
	SignContent []byte
	PubKeys     []ed25519.PublicKey
	PrivKeys    []ed25519.PrivateKey
	Sigs        [][]byte
}

func (c *ed25519DeltaCreator) GetDelta(n int) wspackettest.Ed25519Delta {
	if c.PrivKeys[n] != nil {
		c.Sigs[n] = ed25519.Sign(c.PrivKeys[n], c.SignContent)
		c.PrivKeys[n] = nil
	}

	return wspackettest.Ed25519Delta{
		PubKey: c.PubKeys[n],
		Sig:    c.Sigs[n],
	}
}

func (c *ed25519DeltaCreator) GetDeltaIn(n int) wspackettest.Ed25519Delta {
	return c.GetDelta(n)
}

func (c *ed25519DeltaCreator) GetDeltaOut(n int) wspackettest.Ed25519Delta {
	return c.GetDelta(n)
}

func (c *ed25519DeltaCreator) GetDeltaOutAndPacketIn() (wspackettest.Ed25519Delta, wspackettest.Ed25519PacketIn) {
	d := c.GetDelta(0)

	return d, wspackettest.NewEd25519PacketInForTest(d.PubKey, d.Sig)
}

func (c *ed25519DeltaCreator) GetPacketIn(n int) wspackettest.Ed25519PacketIn {
	d := c.GetDelta(n)

	return wspackettest.NewEd25519PacketInForTest(d.PubKey, d.Sig)
}

func (c *ed25519DeltaCreator) GetDeltaInAndDeltaOut() (
	wspackettest.Ed25519Delta, wspackettest.Ed25519Delta,
) {
	d := c.GetDelta(0)
	return d, d
}

func (c *ed25519DeltaCreator) GetInvalidDelta() wspackettest.Ed25519Delta {
	return wspackettest.Ed25519Delta{
		PubKey: make([]byte, ed25519.PublicKeySize),
		Sig:    make([]byte, ed25519.SignatureSize),
	}
}
