package drbg

import (
    "hash"
    "errors"
    "encoding/binary"
)

const MAX_BYTES = 1 << 27
const MAX_BYTES_PER_GENERATE = 1 << 11

var ErrReseedRequired = errors.New("the DRGB must be reseeded")

// Endianness option
const littleEndian bool = false

func bytesToUint32(in []byte) (out uint32) {
    if littleEndian {
        out = binary.LittleEndian.Uint32(in[0:])
    } else {
        out = binary.BigEndian.Uint32(in[0:])
    }

    return
}

func uint32ToBytes(in uint32) []byte {
    var out [4]byte

    if littleEndian {
        binary.LittleEndian.PutUint32(out[0:], in)
    } else {
        binary.BigEndian.PutUint32(out[0:], in)
    }

    return out[:]
}

func putu64(p []byte, V uint64) {
    if littleEndian {
        binary.LittleEndian.PutUint64(p[0:], V)
    } else {
        binary.BigEndian.PutUint64(p[0:], V)
    }
}

func hashDF(digest hash.Hash, in []byte, out []byte) {
    var counter byte
    var outbits []byte
    var length int

    counter = 0x01

    outlen := len(out)
    outbits = uint32ToBytes(uint32(outlen) << 3)

    var nlength int = 0
    for outlen > 0 {
        digest.Reset()
        digest.Write([]byte{counter})
        digest.Write(outbits)
        digest.Write(in)

        dgst := digest.Sum(nil)

        length = len(dgst)
        if (outlen < length) {
            length = outlen
        }

        copy(out[nlength:], dgst[:length])

        outlen -= length

        nlength += length
        counter++
    }
}

/* seedlen is always >= dgstlen
 *      R0 ...  Ru-v .. .. ..   Ru-1
 *    +          A0    A1 A2 .. Av-1
 */
func drbg_add(R []byte, A []byte, seedlen int) {
    var temp int32 = 0

    for i := seedlen - 1; i >= 0; i-- {
        temp += int32(R[i]) + int32(A[i])
        R[i] = byte(temp & 0xff)
        temp >>= 8
    }
}

func drbg_add1(R []byte, seedlen int) {
    var temp int32 = 1

    for i := seedlen - 1; i >= 0; i-- {
        temp += int32(R[i])
        R[i] = byte(temp & 0xff)
        temp >>= 8
    }
}
