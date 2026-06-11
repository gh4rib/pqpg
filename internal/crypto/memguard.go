package crypto

// Wipe deterministically zeroes out a byte slice to prevent cold-boot RAM extraction.
// The compiler cannot optimize this away because the slice header itself is mutated.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
