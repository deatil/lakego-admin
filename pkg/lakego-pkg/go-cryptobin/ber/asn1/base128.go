package asn1

import "bytes"

// https://en.wikipedia.org/wiki/Variable-length_quantity

func reverseBytes(b []byte) []byte {
    for i, j := 0, len(b)-1; i < len(b)/2; i++ {
        b[i], b[j-i] = b[j-i], b[i]
    }

    return b
}

func encodeBase128(n int) []byte {
    buf := new(bytes.Buffer)

    for n != 0 {
        i := n & 0x7f // b01111111
        n >>= 7

        if len(buf.Bytes()) != 0 {
            i |= 0x80 // b10000000
        }
        buf.WriteByte(byte(i))
    }

    return reverseBytes(buf.Bytes())
}
