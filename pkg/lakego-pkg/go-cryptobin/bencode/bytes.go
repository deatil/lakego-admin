package bencode

import (
    "errors"
    "fmt"
)

// bytes data
type Bytes []byte

var (
    _ Unmarshaler = (*Bytes)(nil)
    _ Marshaler   = (*Bytes)(nil)
    _ Marshaler   = Bytes{}
)

// Unmarshal Bytes
func (me *Bytes) UnmarshalBencode(b []byte) error {
    *me = append([]byte(nil), b...)
    return nil
}

// Marshal Bytes
func (me Bytes) MarshalBencode() ([]byte, error) {
    if len(me) == 0 {
        return nil, errors.New("marshalled Bytes should not be zero-length")
    }

    return me, nil
}

// output string
func (me Bytes) GoString() string {
    return fmt.Sprintf("bencode.Bytes(%q)", []byte(me))
}
