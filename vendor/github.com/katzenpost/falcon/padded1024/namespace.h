/*
 * SPDX-FileCopyrightText: (c) 2026 David Stainton
 * SPDX-License-Identifier: MIT
 *
 * Force-included via cgo CFLAGS so PQClean's common helpers (the
 * fips202 SHA-3/SHAKE family, plus our randombytes trampoline) carry a
 * unique linker symbol per parameter set. Without this rewrite, two
 * PQClean Falcon variants linked into the same Go binary collide on
 * shake256, sha3_384, PQCLEAN_randombytes and the like.
 *
 * The Falcon-specific functions inside codec.c, common.c, fft.c, fpr.c,
 * keygen.c, rng.c, sign.c, vrfy.c and pqclean.c are already namespaced
 * by PQClean's own Zf() macro and need no help.
 */

#ifndef KATZENPOST_FALCON_PADDED1024_NAMESPACE_H
#define KATZENPOST_FALCON_PADDED1024_NAMESPACE_H

/* fips202 (SHAKE/SHA-3) */
#define shake128                  falcon_padded1024_shake128
#define shake256                  falcon_padded1024_shake256
#define shake128_absorb           falcon_padded1024_shake128_absorb
#define shake128_squeezeblocks    falcon_padded1024_shake128_squeezeblocks
#define shake128_ctx_clone        falcon_padded1024_shake128_ctx_clone
#define shake128_ctx_release      falcon_padded1024_shake128_ctx_release
#define shake128_inc_init         falcon_padded1024_shake128_inc_init
#define shake128_inc_absorb       falcon_padded1024_shake128_inc_absorb
#define shake128_inc_finalize     falcon_padded1024_shake128_inc_finalize
#define shake128_inc_squeeze      falcon_padded1024_shake128_inc_squeeze
#define shake128_inc_ctx_clone    falcon_padded1024_shake128_inc_ctx_clone
#define shake128_inc_ctx_release  falcon_padded1024_shake128_inc_ctx_release
#define shake256_absorb           falcon_padded1024_shake256_absorb
#define shake256_squeezeblocks    falcon_padded1024_shake256_squeezeblocks
#define shake256_ctx_clone        falcon_padded1024_shake256_ctx_clone
#define shake256_ctx_release      falcon_padded1024_shake256_ctx_release
#define shake256_inc_init         falcon_padded1024_shake256_inc_init
#define shake256_inc_absorb       falcon_padded1024_shake256_inc_absorb
#define shake256_inc_finalize     falcon_padded1024_shake256_inc_finalize
#define shake256_inc_squeeze      falcon_padded1024_shake256_inc_squeeze
#define shake256_inc_ctx_clone    falcon_padded1024_shake256_inc_ctx_clone
#define shake256_inc_ctx_release  falcon_padded1024_shake256_inc_ctx_release
#define sha3_256                  falcon_padded1024_sha3_256
#define sha3_256_inc_init         falcon_padded1024_sha3_256_inc_init
#define sha3_256_inc_absorb       falcon_padded1024_sha3_256_inc_absorb
#define sha3_256_inc_finalize     falcon_padded1024_sha3_256_inc_finalize
#define sha3_256_inc_ctx_clone    falcon_padded1024_sha3_256_inc_ctx_clone
#define sha3_256_inc_ctx_release  falcon_padded1024_sha3_256_inc_ctx_release
#define sha3_384                  falcon_padded1024_sha3_384
#define sha3_384_inc_init         falcon_padded1024_sha3_384_inc_init
#define sha3_384_inc_absorb       falcon_padded1024_sha3_384_inc_absorb
#define sha3_384_inc_finalize     falcon_padded1024_sha3_384_inc_finalize
#define sha3_384_inc_ctx_clone    falcon_padded1024_sha3_384_inc_ctx_clone
#define sha3_384_inc_ctx_release  falcon_padded1024_sha3_384_inc_ctx_release
#define sha3_512                  falcon_padded1024_sha3_512
#define sha3_512_inc_init         falcon_padded1024_sha3_512_inc_init
#define sha3_512_inc_absorb       falcon_padded1024_sha3_512_inc_absorb
#define sha3_512_inc_finalize     falcon_padded1024_sha3_512_inc_finalize
#define sha3_512_inc_ctx_clone    falcon_padded1024_sha3_512_inc_ctx_clone
#define sha3_512_inc_ctx_release  falcon_padded1024_sha3_512_inc_ctx_release

/* randombytes shim */
#define PQCLEAN_randombytes       falcon_padded1024_PQCLEAN_randombytes

#endif
