package asn1

import (
    "math/big"
)
// ENUMERATED

// An Enumerated is represented as a plain int.
type Enumerated int

type intEncoder int

func (e intEncoder) length() int {
    length := 1

    for e > 127 {
        length++
        e >>= 8
    }

    for e < -128 {
        length++
        e >>= 8
    }

    return length
}

func (e intEncoder) encode() ([]byte, error) {
    length := e.length()
    buf := make([]byte, length)
    for j := 0; j < length; j++ {
        shift := uint((length - 1 - j) * 8)
        buf[j] = byte(e >> shift)
    }

    return buf, nil
}

var (
    byte00Encoder encoder = byteEncoder(0x00)
    byteFFEncoder encoder = byteEncoder(0xff)
)

func makeBigInt(n *big.Int) (encoder, error) {
    if n == nil {
        return nil, StructuralError{"empty integer"}
    }

    if n.Sign() < 0 {
        // A negative number has to be converted to two's-complement
        // form. So we'll invert and subtract 1. If the
        // most-significant-bit isn't set then we'll need to pad the
        // beginning with 0xff in order to keep the number negative.
        nMinus1 := new(big.Int).Neg(n)
        nMinus1.Sub(nMinus1, bigOne)
        bytes := nMinus1.Bytes()
        for i := range bytes {
            bytes[i] ^= 0xff
        }
        
        if len(bytes) == 0 || bytes[0]&0x80 == 0 {
            return multiEncoder([]encoder{byteFFEncoder, bytesEncoder(bytes)}), nil
        }
        
        return bytesEncoder(bytes), nil
    } else if n.Sign() == 0 {
        // Zero is written as a single 0 zero rather than no bytes.
        return byte00Encoder, nil
    } else {
        bytes := n.Bytes()
        if len(bytes) > 0 && bytes[0]&0x80 != 0 {
            // We'll have to pad this with 0x00 in order to stop it
            // looking like a negative number.
            return multiEncoder([]encoder{byte00Encoder, bytesEncoder(bytes)}), nil
        }
        
        return bytesEncoder(bytes), nil
    }
}