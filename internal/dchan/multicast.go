package dchan

// Multicast is a linked list of event-driven values.
// The list has a single writer and many readers.
// Readers can each consume the list at their own pace.
//
// If readers do not actively consume the list,
// the node they observe will never be garbage collected,
// which is a memory leak.
type Multicast[T any] struct {
	Ready chan struct{}
	Next  *Multicast[T]
	Val   T
}

// NewMulticast returns an initialized multicast value.
func NewMulticast[T any]() *Multicast[T] {
	return &Multicast[T]{
		Ready: make(chan struct{}),
	}
}

// Set assigns m's value and initializes m.Next.
// Then m.Ready is closed, notifying any observers that
// m.Val can now be safely read.
//
// If Set is called twice for the same m, Set panics.
func (m *Multicast[T]) Set(t T) {
	m.Val = t
	m.Next = NewMulticast[T]()
	close(m.Ready)
}
