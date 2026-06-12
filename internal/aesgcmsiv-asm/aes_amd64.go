//go:build amd64 && !gccgo && !appengine
// +build amd64,!gccgo,!appengine

package siv

// keySchedule performs an AES key-schedule and is implemented in aes_amd64.s
func keySchedule(keys, key []byte)

// encryptBlock encrypts one 128 bit block from src to dst using AES and is
// implemented in aes_amd64.s
func encryptBlock(dst, src, keys []byte, keyLen uint64)
