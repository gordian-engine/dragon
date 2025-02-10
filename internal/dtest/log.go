package dtest

import (
	"log/slog"
	"testing"

	"github.com/neilotoole/slogt"
)

// NewLogger returns a *slog.Logger associated with the test t.
func NewLogger(t testing.TB) *slog.Logger {
	// The slogt package has been stable and effective
	// for adapting slog to testing.T.Log calls.
	// Prefer to abstract slogt behind a dtest interface
	// to reduce a direct dependency from tests to an external module.
	return slogt.New(t, slogt.Text())
}
