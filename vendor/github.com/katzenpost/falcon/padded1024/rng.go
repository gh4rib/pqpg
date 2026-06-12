// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: MIT

package padded1024

// #include <stdint.h>
// #include <stddef.h>
import "C"

import (
	"crypto/rand"
	"io"
	"sync"
	"unsafe"
)

var (
	rngMu sync.RWMutex
	rng   io.Reader = rand.Reader
)

// SetTestRNG redirects the source of randomness used by the underlying
// C library to r, returning a function that restores the previous
// reader. Concurrent use with key generation or signing is undefined;
// it is intended only for use in tests, paired with t.Cleanup. Pass
// nil to reset to crypto/rand.
func SetTestRNG(r io.Reader) (restore func()) {
	if r == nil {
		r = rand.Reader
	}
	rngMu.Lock()
	prev := rng
	rng = r
	rngMu.Unlock()
	return func() {
		rngMu.Lock()
		rng = prev
		rngMu.Unlock()
	}
}

//export go_falcon_padded1024_randombytes
func go_falcon_padded1024_randombytes(out *C.uint8_t, n C.size_t) C.int {
	if n == 0 {
		return 0
	}
	rngMu.RLock()
	src := rng
	rngMu.RUnlock()
	buf := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(n))
	if _, err := io.ReadFull(src, buf); err != nil {
		return -1
	}
	return 0
}
