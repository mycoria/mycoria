package frame

import (
	"sync"
	"sync/atomic"
)

// Builder builds and parses frames.
// It holds internal pools of frames and slices for efficiency.
type Builder struct {
	fiveHBytePool      sync.Pool
	fifteenHBytePool   sync.Pool
	fiveKBytePool      sync.Pool
	sixtyFiveKBytePool sync.Pool

	frameV1Pool sync.Pool

	// Margins
	offset   atomic.Int32
	overhead atomic.Int32
}

const (
	fiveHByteSize      = 500 + 100
	fifteenHByteSize   = 1500 + 100
	fiveKByteSize      = 5000 + 100
	sixtyFiveKByteSize = 65535 + 40 + 100 // Max IPv6 packet size + IPv6 header
)

// NewFrameBuilder returns a new frame builder.
func NewFrameBuilder() *Builder {
	b := &Builder{
		fiveHBytePool: sync.Pool{
			New: func() any { return make([]byte, fiveHByteSize) },
		},
		fifteenHBytePool: sync.Pool{
			New: func() any { return make([]byte, fifteenHByteSize) },
		},
		fiveKBytePool: sync.Pool{
			New: func() any { return make([]byte, fiveKByteSize) },
		},
		sixtyFiveKBytePool: sync.Pool{
			New: func() any { return make([]byte, sixtyFiveKByteSize) },
		},
	}
	// Set pools with self-reference.
	b.frameV1Pool = sync.Pool{
		New: func() any { return &FrameV1{builder: b} },
	}
	return b
}

// GetPooledSlice returns a slice from the pool (or creates one) that has
// at least the specified size.
func (b *Builder) GetPooledSlice(minSize int) (pooledSlice []byte) {
	switch {
	case minSize <= fiveHByteSize:
		return b.fiveHBytePool.Get().([]byte) //nolint:forcetypeassert
	case minSize <= fifteenHByteSize:
		return b.fifteenHBytePool.Get().([]byte) //nolint:forcetypeassert
	case minSize <= fiveKByteSize:
		return b.fiveKBytePool.Get().([]byte) //nolint:forcetypeassert
	case minSize <= sixtyFiveKByteSize:
		return b.sixtyFiveKBytePool.Get().([]byte) //nolint:forcetypeassert
	default:
		// Required min size cannot be satisfied.
		return nil
	}
}

// ReturnPooledSlice returns the give pooled slice to the pool.
// The provided slice must not be used anymore in any way.
func (b *Builder) ReturnPooledSlice(pooledSlice []byte) {
	//nolint:forcetypeassert

	// Revert slice back to original size.
	pooledSlice = pooledSlice[0:cap(pooledSlice)]
	// Reset slice to zero.
	clear(pooledSlice)
	// Put slice back into correct pool.
	switch len(pooledSlice) {
	case fiveHByteSize:
		b.fiveHBytePool.Put(pooledSlice) //nolint:staticcheck
	case fifteenHByteSize:
		b.fifteenHBytePool.Put(pooledSlice) //nolint:staticcheck
	case fiveKByteSize:
		b.fiveKBytePool.Put(pooledSlice) //nolint:staticcheck
	case sixtyFiveKByteSize:
		b.sixtyFiveKBytePool.Put(pooledSlice) //nolint:staticcheck
	default:
		// Provided slice does not match any pools.
	}
}

// FrameMargins returns the currently required margins for frames.
func (b *Builder) FrameMargins() (offset, overhead int) {
	return int(b.offset.Load()), int(b.overhead.Load())
}

// SetFrameMargins sets new required margins for new frames.
// Values must be between 0 and 100 (inclusive).
func (b *Builder) SetFrameMargins(offset, overhead int) {
	if offset >= 0 && offset <= 100 {
		b.offset.Store(int32(offset))
	}
	if overhead >= 0 && overhead <= 100 {
		b.overhead.Store(int32(overhead))
	}
}
