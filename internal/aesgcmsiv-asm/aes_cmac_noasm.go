// +build !amd64 gccgo appengine

package siv

type aesSivCMacImpl = aesSivCMacGeneric

func newCMAC(key []byte) aead { return newCMACGeneric(key) }
