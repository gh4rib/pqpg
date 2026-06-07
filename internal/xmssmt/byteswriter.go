package xmssmt

import (
	"errors"
	"io"
)

// A Writer implements io.Writer and io.Seeker by writing to the
// given byteslice.  Unlike a bytes.Buffer, BytesWriter does not resize
// the byte slice.
type Writer struct {
	buf    []byte
	offset int64
}

// Create a new writer using the given buffer
func NewWriter(buf []byte) *Writer {
	return &Writer{
		buf: buf,
	}
}

func (w *Writer) Write(p []byte) (n int, err error) {
	copy(w.buf[w.offset:], p)
	w.offset += int64(len(p))
	if w.offset > int64(len(w.buf)) {
		n = int(w.offset) - len(w.buf)
		w.offset = int64(len(w.buf))
		return n, errors.New("byteswriter.Writer: out of bounds write")
	}
	return len(p), nil
}

func (w *Writer) Seek(offset int64, whence int) (int64, error) {
	var offset2 int64
	switch whence {
	case io.SeekStart:
		offset2 = offset
	case io.SeekCurrent:
		offset2 = w.offset + offset
	case io.SeekEnd:
		offset2 = w.offset - offset
	}
	if offset2 < 0 || offset2 > int64(len(w.buf)) {
		return w.offset, errors.New("byteswriter.Writer: out of bounds seek")
	}
	w.offset = offset2
	return w.offset, nil
}
