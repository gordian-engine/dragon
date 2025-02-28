package dtest

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// TimeFactor is a multiplier that can be controlled by the
// DRAGON_TEST_TIME_FACTOR environment variable
// to increase test-related timeouts.
//
// While a flat 100ms timer usually suffices on a workstation,
// that duration may not suffice on a contended CI machine.
// Rather than requiring tests to be changed to use a longer timeout,
// the operator can set e.g. DRAGON_TEST_TIME_FACTOR=3
// to triple how long the timeouts are.
//
// The variable is exported in case programmatic control
// outside of environment variables is needed.
var TimeFactor ScaledDuration = 1

func init() {
	f := os.Getenv("DRAGON_TEST_TIME_FACTOR")
	if f == "" {
		return
	}

	n, err := strconv.Atoi(f)
	if err != nil {
		panic(fmt.Errorf(
			"failed to parse DRAGON_TEST_TIME_FACTOR (%q) into an integer: %w",
			f, err,
		))
	}

	if n <= 0 {
		panic(fmt.Errorf("DRAGON_TEST_TIME_FACTOR must be positive; got %d", n))
	}

	TimeFactor = ScaledDuration(n)
}

type ScaledDuration time.Duration

// ScaleMs returns ms in milliseconds, multiplied by [TimeFactor]
// so that test timeouts can be easily adjusted for machines running under load.
//
// This type is used in [SendOrTimeout] and [ReceiveOrTimeout]
// to ensure callers do not use literal timeout values,
// which would cause flaky tests on slower machines.
func ScaleMs(ms int64) ScaledDuration {
	return TimeFactor * ScaledDuration(ms) * ScaledDuration(time.Millisecond)
}

// Sleep calls [time.Sleep] with the given scaled duration,
// to avoid a consumer of dtest needing to convert between a ScaledDuration and a time.Duration.
func Sleep(dur ScaledDuration) {
	time.Sleep(time.Duration(dur))
}
