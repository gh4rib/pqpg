//go:build !amd64 || gccgo || appengine
// +build !amd64 gccgo appengine

package siv

func newGCM(key []byte) aead { return newGCMGeneric(key) }
