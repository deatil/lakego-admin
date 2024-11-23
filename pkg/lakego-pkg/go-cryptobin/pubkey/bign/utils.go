package bign

import (
    "math"
    "errors"
    "math/big"
    "crypto/subtle"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/hash/belt"
)

func putu32(ptr []byte, a uint32) {
    binary.LittleEndian.PutUint32(ptr, a)
}

func mathMin(a, b int) int {
    if a < b {
        return a
    }

    return b
}

// Reverse bytes
func reverse(d []byte) []byte {
    for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
        d[i], d[j] = d[j], d[i]
    }

    return d
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

/* The additional data for bign are specific. We provide
 * helpers to extract them from an adata pointer.
 */
func GetOidFromAdata(adata []byte) (oid []byte, err error) {
    if len(adata) == 0 || len(adata) < 4 {
        return nil, errors.New("adata too short")
    }

    adatalen := uint16(len(adata))

    oidlen := uint16(adata[0]) << 8 | uint16(adata[1])
    tlen := uint16(adata[2]) << 8 | uint16(adata[3])

    if (oidlen + tlen) < tlen || (oidlen + tlen) > (adatalen - 4) {
        return nil, errors.New("adata error")
    }

    return adata[4:4+oidlen], nil
}

func GetTFromAdata(adata []byte) (t []byte, err error) {
    if len(adata) == 0 || len(adata) < 4 {
        return nil, errors.New("adata too short")
    }

    adatalen := uint16(len(adata))

    oidlen := uint16(adata[0]) << 8 | uint16(adata[1])
    tlen := uint16(adata[2]) << 8 | uint16(adata[3])

    if (oidlen + tlen) < tlen || (oidlen + tlen) > (adatalen - 4) {
        return nil, errors.New("adata error")
    }

    return adata[4+oidlen:4+oidlen+tlen], nil
}

func MakeAdata(oid, t []byte) (adata []byte) {
    adata = make([]byte, 4 + len(oid) + len(t))

    oidlen := len(oid)
    tlen := len(t)

    if oidlen > 0 {
        adata[0] = byte(oidlen >> 8)
        adata[1] = byte(oidlen & 0xff)
        copy(adata[4:], oid)
    } else{
        adata[0] = 0
        adata[1] = 0
    }

    if tlen > 0 {
        adata[2] = byte(tlen >> 8)
        adata[3] = byte(tlen & 0xff)
        copy(adata[4 + oidlen:], t)
    } else{
        adata[2] = 0
        adata[3] = 0
    }

    return adata
}

const BELT_BLOCK_LEN = 16
const MAX_DIGEST_SIZE = 64

func determiniticNonce(
    k, q *big.Int,
    qBitLen int,
    x *big.Int,
    adata []byte,
    h []byte,
) error {
    qlen := (qBitLen + 7) / 8
    l := qlen / 2
    hlen := len(h)

    beltHash := belt.New()

    oid, err := GetOidFromAdata(adata)
    if err != nil {
        return err
    }

    t, err := GetTFromAdata(adata)
    if err != nil {
        return err
    }

    beltHash.Write(oid)

    /* Put the private key in a string <d>2*l */
    FE2OS_D := make([]byte, qlen)
    x.FillBytes(FE2OS_D)
    reverse(FE2OS_D)

    /* Only hash the 2*l bytes of d */
    beltHash.Write(FE2OS_D[:2*l])

    beltHash.Write(t)

    theta := beltHash.Sum(nil)

    /* n is the number of 128 bits blocks in H */
    n := uint(hlen / BELT_BLOCK_LEN)

    rlen := ((MAX_DIGEST_SIZE / BELT_BLOCK_LEN) * BELT_BLOCK_LEN) + (2 * BELT_BLOCK_LEN)

    r := make([]byte, rlen)
    copy(r, h)

    /* If we have less than two blocks for the input hash size, we use zero
     * padding to achieve at least two blocks.
     * NOTE: this is not in the standard but allows to be compatible with small
     * size hash functions.
     */
    if n <= 1 {
        n = 2
    }

    var i uint32 = 1
    var j, z uint

    r_bar := make([]byte, rlen)

    for {
        var s [BELT_BLOCK_LEN]byte = [BELT_BLOCK_LEN]byte{}
        var i_block [BELT_BLOCK_LEN]byte

        /* Put the xor of all n-1 elements in s */
        for j = 0; j < (n - 1); j++ {
            for z = 0; z < BELT_BLOCK_LEN; z++ {
                s[z] ^= r[(BELT_BLOCK_LEN * j) + z]
            }
        }

        copy(r[:], r[BELT_BLOCK_LEN:(n - 1) * BELT_BLOCK_LEN])

        /* r_n-1 = belt-block(s, theta) ^ r_n ^ <i>128 */
        putu32(i_block[:], i)

        var rr [BELT_BLOCK_LEN]byte
        copy(rr[:], r[(n - 2) * BELT_BLOCK_LEN:])

        var tmptheta [32]byte
        copy(tmptheta[:], theta[:])
        belt.BeltEncrypt(s, &rr, tmptheta)

        copy(r[(n - 2) * BELT_BLOCK_LEN:], rr[:])

        for z = 0; z < BELT_BLOCK_LEN; z++ {
            r[((n - 2) * BELT_BLOCK_LEN) + z] ^= (r[((n - 1) * BELT_BLOCK_LEN) + z] ^ i_block[z])
        }

        /* r_n = s */
        copy(r[(n - 1) * BELT_BLOCK_LEN:], s[:BELT_BLOCK_LEN])

        var r_bar_len int
        if qlen < int(n * BELT_BLOCK_LEN) {
            r_bar_len = qlen
            copy(r_bar[:], r[:r_bar_len])

            if (qBitLen % 8) != 0 {
                r_bar[r_bar_len - 1] &= byte((0x1 << (qBitLen % 8)) - 1)
            }
        } else {
            if (n * BELT_BLOCK_LEN) > 0xffff {
                return errors.New("n error")
            }

            r_bar_len = int(n * BELT_BLOCK_LEN)

            copy(r_bar[:], r[:r_bar_len])
        }

        reverse(r_bar[:r_bar_len])

        k.SetBytes(r_bar[:r_bar_len])

        if (i >= 2 * uint32(n)) && k.Cmp(q) < 0 && k.Cmp(zero) != 0 {
            break
        }

        i++

        /* If we have wrapped (meaning i > 2^32), we exit with failure */
        if i >= math.MaxUint32 {
            return errors.New("gen fail")
        }
    }

    return nil
}
