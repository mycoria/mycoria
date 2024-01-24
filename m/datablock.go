package m

import (
	"encoding/binary"
	"errors"
)

// GetDataBlock returns the varint-length-prefixes data block at the start of the given data slice.
// It returns how many bytes were read and a slice reference to the block.
func GetDataBlock(data []byte) (n int, block []byte, err error) {
	// Get varint for block size.
	number, n := binary.Uvarint(data)
	if n == 0 {
		return 0, nil, errors.New("varint: not enough data")
	}
	if n < 0 {
		return 0, nil, errors.New("varint: encoded integer greater than uint64")
	}
	if n > 0x7FFFFFFF {
		return 0, nil, errors.New("varint: encoded integer greater than int32")
	}
	length := int(number)

	// Get block.
	if len(data) < n+length {
		return 0, nil, errors.New("not enough data for block")
	}
	return n + length, data[n : n+length], nil
}

// PutDataBlock encodes the src data to dst with a varint-length-prefix.
// It returns how many bytes were written.
func PutDataBlock(dst []byte, src []byte) (n int, err error) {
	srcLen := uint64(len(src))
	if len(dst) < varintSize(srcLen)+len(src) {
		return 0, errors.New("not enough space for data")
	}
	n += binary.PutUvarint(dst, uint64(len(src)))
	n += copy(dst[n:], src)
	return n, nil
}

// varintSize returns the size required to block encode the data block.
func varintSize(n uint64) (size int) {
	switch {
	case n < 1<<7: // < 128
		return 1
	case n < 1<<14: // < 16384
		return 2
	case n < 1<<21: // < 2097152
		return 3
	case n < 1<<28: // < 268435456
		return 4
	case n < 1<<35: // < 34359738368
		return 5
	case n < 1<<42: // < 4398046511104
		return 6
	case n < 1<<49: // < 562949953421312
		return 7
	case n < 1<<56: // < 72057594037927936
		return 8
	case n < 1<<63: // < 9223372036854775808
		return 9
	default:
		return 10
	}
}
