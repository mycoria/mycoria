package m

// SafeString returns the given ascii string cleaned from potentially
// disruptive characters. The readability of the result is not great.
// It's not meant for general use, but to be able to print or log
// untrusted input with some safety.
func SafeString(s string) string {
	b := []byte(s)
	for i, c := range b {
		b[i] = safeCharacter(c)
	}
	return string(b)
}

func safeCharacter(c byte) byte {
	// Check for basic safe range.
	if c < 33 || c > 122 {
		return '.'
	}

	// Other potentially disruptive characters.
	switch c {
	case 34, // "
		36, // $
		37, // %
		38, // &
		39, // '
		40, // (
		41, // )
		59, // ;
		60, // <
		62, // >
		92, // \
		96: // `
		return '.'
	}

	return c
}
