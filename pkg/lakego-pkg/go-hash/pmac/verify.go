package pmac

import (
    "crypto/cipher"
    "crypto/subtle"
)

// Sum computes the PMAC checksum with the given tagsize of msg using the cipher.Block.
func Sum(msg []byte, c cipher.Block, tagsize int) ([]byte, error) {
    h, err := NewWithTagSize(c, tagsize)
    if err != nil {
        return nil, err
    }

    h.Write(msg)
    return h.Sum(nil), nil
}

// Verify computes the PMAC checksum with the given tagsize of msg and compares
// it with the given mac. This functions returns true if and only if the given mac
// is equal to the computed one.
func Verify(mac, msg []byte, c cipher.Block, tagsize int) bool {
    sum, err := Sum(msg, c, tagsize)
    if err != nil {
        return false
    }

    return subtle.ConstantTimeCompare(mac, sum) == 1
}
