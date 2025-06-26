// Package dpubsub contains types for in-application
// publish-subscribe patterns.
//
// The [Stream] type specifically simplifies the pattern of
// a single publisher with many concurrent subscribers,
// who all need to observe the same sequence of values.
package dpubsub
