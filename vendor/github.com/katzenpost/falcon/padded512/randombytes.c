// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: MIT
//
// Replaces PQClean's OS-randomness portability layer with a trampoline
// into the surrounding Go package. Production callers receive bytes
// from crypto/rand; tests can install a deterministic source (such as
// the AES-256 CTR_DRBG used by the NIST PQC KAT framework) by calling
// padded512.SetTestRNG before invoking GenerateKey or Sign.
//
// The randombytes.h header in this package macros the public symbol
// `randombytes` to `PQCLEAN_randombytes`, so this file in fact defines
// PQCLEAN_randombytes; the Falcon C calls into it via the same macro
// and reaches our shim transparently.

#include "randombytes.h"

extern int go_falcon_padded512_randombytes(uint8_t *out, size_t n);

int randombytes(uint8_t *out, size_t n) {
    return go_falcon_padded512_randombytes(out, n);
}
