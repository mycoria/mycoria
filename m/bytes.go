package m

// GetUint16 returns a uint16 from the first two bytes of the given byte slice.
func GetUint16(b []byte) uint16 {
	return uint16(b[1]) | uint16(b[0])<<8
}

// PutUint16 writes the uint16 to the first two bytes of the given byte slice.
func PutUint16(dst []byte, src uint16) {
	dst[1] = byte(src)
	dst[0] = byte(src >> 8)
}

// GetUint32 returns a uint32 from the first four bytes of the given byte slice.
func GetUint32(b []byte) uint32 {
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}

// PutUint32 writes the uint32 to the first four bytes of the given byte slice.
func PutUint32(dst []byte, src uint32) {
	dst[3] = byte(src)
	dst[2] = byte(src >> 8)
	dst[1] = byte(src >> 16)
	dst[0] = byte(src >> 24)
}

// GetUint64 returns a uint64 from the first eight bytes of the given byte slice.
func GetUint64(b []byte) uint64 {
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}

// PutUint64 writes the uint64 to the first eight bytes of the given byte slice.
func PutUint64(dst []byte, src uint64) {
	dst[7] = byte(src)
	dst[6] = byte(src >> 8)
	dst[5] = byte(src >> 16)
	dst[4] = byte(src >> 24)
	dst[3] = byte(src >> 32)
	dst[2] = byte(src >> 40)
	dst[1] = byte(src >> 48)
	dst[0] = byte(src >> 56)
}
