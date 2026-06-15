//go:build linux && (amd64 || arm64)

package oqs

// C callbacks, DO NOT CHANGE

/*
#cgo CFLAGS: -I/home/daud/Documents/PQC/pqpg-cloudflare-circl/liboqs/oqs_static_env/include
#cgo LDFLAGS: /home/daud/Documents/PQC/pqpg-cloudflare-circl/liboqs/oqs_static_env/lib/liboqs.a -lm
#include <stdint.h>
#include <stddef.h>
void randAlgorithmPtr_cgo(uint8_t* random_array, size_t bytes_to_read) {
	void randAlgorithmPtr(uint8_t*, size_t);
	randAlgorithmPtr(random_array, bytes_to_read);
}
*/
import "C"
