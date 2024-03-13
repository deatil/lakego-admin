package xoodyak

import (
    "hash"
)

// NewXoodyakMac generates a new hashing object with the provided key data already baked in. Writing
// Any data then written to the hash object is part of the MAC check. Note that the length of the
// resulting MAC matches that of the official Xoodyak hash output: 32 bytes
func NewXoodyakMac(key []byte) hash.Hash {
    d := &digest{absorbCd: AbsorbCdInit}
    xk := Instantiate(key, []byte{}, []byte{})
    d.xk = xk
    d.x = make([]byte, xk.AbsorbSize)
    return d
}

// MACXoodyak generates a message authentication code of the desired length in bytes for the provided
// message based on the provided key data.
// This implements the MAC behavior described in section 1.3.2 of the Xoodyak specification.
func MACXoodyak(key, msg []byte, macLen uint) []byte {
    xkMAC := Instantiate(key, nil, nil)
    xkMAC.Absorb(msg)
    return xkMAC.Squeeze(macLen)
}
