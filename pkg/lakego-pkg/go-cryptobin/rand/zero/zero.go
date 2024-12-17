package zero

import (
    "io"
)

// zero Reader
type zeroReader struct {
    io.Reader
}

func (this *zeroReader) Read(dst []byte) (n int, err error) {
    for i := range dst {
        dst[i] = 0
    }

    return len(dst), nil
}

var Reader = &zeroReader{}
