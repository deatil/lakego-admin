package kcdsa

import (
    "io"
    "hash"
    "math/big"
    "crypto/subtle"
    "encoding/binary"
)

type GeneratedParameter struct {
    P     *big.Int
    Q     *big.Int
    G     *big.Int
    J     *big.Int
    Seed  []byte
    Count int
    H     *big.Int
}

func GenerateParametersFast(rand io.Reader, d ParameterSize) (generated GeneratedParameter, err error) {
    P, Q, G := new(big.Int), new(big.Int), new(big.Int)

    buf := make([]byte, bitsToBytes(d.A))

    tmp := new(big.Int)
    F := new(big.Int)

GeneratePrimes:
    for {
        if buf, err = ReadBits(buf, rand, d.B); err != nil {
            return
        }
        buf[len(buf)-1] |= 1
        Q.SetBytes(buf)
        Q.SetBit(Q, d.B-1, 1)

        if !Q.ProbablyPrime(NumMRTests) {
            continue
        }

        for i := 0; i < 4*d.A; i++ {
            if buf, err = ReadBits(buf, rand, d.A); err != nil {
                return
            }
            buf[len(buf)-1] |= 1
            P.SetBytes(buf)
            P.SetBit(P, d.A-1, 1)

            // P - (P % Q) - 1
            P.Sub(P, tmp.Sub(tmp.Mod(P, Q), One))
            if P.BitLen() < d.A {
                continue
            }

            if !P.ProbablyPrime(NumMRTests) {
                continue
            }

            break GeneratePrimes
        }
    }

    tmp.Div(tmp.Sub(P, One), Q)

    for {
        if buf, err = ReadBits(buf, rand, d.A); err != nil {
            return
        }
        F.SetBytes(buf)
        F.Add(F, Two)
        if F.Cmp(P) >= 0 {
            continue
        }

        G.Exp(F, tmp, P)
        if G.Cmp(One) <= 0 {
            continue
        }
        if G.Cmp(P) >= 0 {
            continue
        }

        break
    }

    return GeneratedParameter{
        P: P,
        Q: Q,
        G: G,
    }, nil
}

func generateParametersTTAK(rand io.Reader, ps ParameterSize) (generated GeneratedParameter, err error) {
    h := ps.NewHash()

    generated.J = new(big.Int)
    generated.P = new(big.Int)
    generated.Q = new(big.Int)
    generated.H = new(big.Int)
    generated.G = new(big.Int)

    // p. 13
    generated.Seed = make([]byte, bitsToBytes(ps.B))

    var ok bool
    var buf []byte
    for {
        _, err = io.ReadFull(rand, generated.Seed)
        if err != nil {
            return
        }

        // 2 ~ 4
        buf, ok = GenerateJ(generated.J, buf, generated.Seed, h, ps)
        if !ok {
            continue
        }

        // 5 ~ 12
        buf, generated.Count, ok = GeneratePQ(generated.P, generated.Q, buf, generated.J, generated.Seed, h, ps)
        if !ok {
            continue
        }

        _, err = GenerateHG(generated.H, generated.G, buf, rand, generated.P, generated.J)
        if err != nil {
            return
        }

        return
    }
}

func RegeneratePQ(
    ps ParameterSize,
    J *big.Int,
    seed []byte,
    count int,
) (
    P, Q *big.Int,
    ok bool,
) {
    P = new(big.Int)
    Q = new(big.Int)

    var CountB [4]byte
    binary.BigEndian.PutUint32(CountB[:], uint32(count))

    buf := make([]byte, bitsToBytes(ps.B))

    U := ppgf(buf, ps.B, ps.NewHash(), seed, CountB[:])

    U[len(U)-1] |= 1
    Q.SetBytes(U)
    Q.SetBit(Q, ps.B-1, 1)

    P.Add(P.Lsh(P.Mul(J, Q), 1), One)
    if P.BitLen() > ps.A {
        return nil, nil, false
    }

    if !Q.ProbablyPrime(NumMRTests) {
        return nil, nil, false
    }

    if !P.ProbablyPrime(NumMRTests) {
        return nil, nil, false
    }

    return P, Q, true
}

func GenerateJ(
    J *big.Int, buf []byte,
    seed []byte,
    h hash.Hash,
    d ParameterSize,
) (bufNew []byte, ok bool) {
    bufNew = ppgf(buf, d.A-d.B-4, h, seed)

    bufNew[len(bufNew)-1] |= 1
    J.SetBytes(bufNew)
    J.SetBit(J, d.A-d.B-1, 1)

    if !J.ProbablyPrime(NumMRTests) {
        return
    }

    ok = true
    return
}

func GeneratePQ(
    P, Q *big.Int, buf []byte,
    J *big.Int,
    seed []byte,
    h hash.Hash,
    d ParameterSize,
) (bufNew []byte, count int, ok bool) {
    count = 0

    var countB [4]byte

    bufNew = Grow(buf, bitsToBytes(d.B))
    ppgf := newPPGF(h, seed)

    for count <= (1 << 24) {
        incCtr(countB[:])
        count += 1

        bufNew = ppgf.Generate(bufNew, d.B, countB[:])

        bufNew[len(bufNew)-1] |= 1
        Q.SetBytes(bufNew)
        Q.SetBit(Q, d.B-1, 1)

        P.Add(P.Lsh(P.Mul(J, Q), 1), One)
        if P.BitLen() > d.A {
            continue
        }

        if !Q.ProbablyPrime(NumMRTests) {
            continue
        }

        if !P.ProbablyPrime(NumMRTests) {
            continue
        }

        ok = true
        return
    }

    return
}

func GenerateHG(
    H, G *big.Int,
    buf []byte,
    rand io.Reader,
    P, J *big.Int,
) (bufOut []byte, err error) {
    for {
        bufOut, err = ReadBigInt(H, rand, buf, P)
        if err != nil {
            return
        }
        H.Add(H, Two)

        ok := GenerateG(G, P, J, H)
        if !ok {
            continue
        }

        return
    }
}

func GenerateG(
    G *big.Int,
    P, J, H *big.Int,
) (ok bool) {
    G.Set(J)
    G.Lsh(G, 1)
    G.Exp(H, G, P)

    return G.Cmp(One) != 0
}

func GenerateX(
    X *big.Int,
    Q *big.Int, upri, xkey []byte, h hash.Hash, d ParameterSize,
) {
    xseed := ppgf(nil, d.B, h, upri)

    var carry int
    xval := make([]byte, bitsToBytes(d.B))
    for i := 0; i < len(xseed); i++ {
        idx := len(xseed) - i - 1
        sum := int(xseed[idx]) + carry

        if i < len(xkey) {
            sum += int(xkey[len(xkey)-i-1])
        }

        xval[idx] = byte(sum)
        carry = sum >> 8
    }
    xval = RightMost(xval, d.B)

    X.SetBytes(ppgf(xseed, d.B, h, xval))
    X.Mod(X, Q)
}

func GenerateY(
    Y *big.Int,
    P, Q, G, X *big.Int,
) {
    xInv := FermatInverse(X, Q)

    Y.Exp(G, xInv, P)
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

func bitsToBytes(bits int) int {
    return (bits+7)/8
}

// without guarantee of data
func Grow(buf []byte, bytes int) []byte {
    if bytes < cap(buf) {
        return buf[:bytes]
    } else {
        return make([]byte, bytes)
    }
}

// resize dst, ReadFull, cut from right
func ReadBits(dst []byte, rand io.Reader, bits int) ([]byte, error) {
    bytes := bitsToBytes(bits)

    dst = Grow(dst, bytes)

    if _, err := io.ReadFull(rand, dst); err != nil {
        return dst, err
    }

    bytes = bits & 0x07
    if bytes != 0 {
        dst[0] &= byte((1 << bytes) - 1)
    }

    return dst, nil
}

// resize dst, ReadFull, cut from right
func ReadBytes(dst []byte, rand io.Reader, bytes int) ([]byte, error) {
    dst = Grow(dst, bytes)

    if _, err := io.ReadFull(rand, dst); err != nil {
        return dst, err
    }

    return dst, nil
}

// 0 0[0 0 0 0 0 0]
func RightMost(b []byte, bits int) []byte {
    bytes := bitsToBytes(bits)
    if len(b) >= bytes {
        b = b[len(b)-bytes:]
    }

    remain := bits % 8
    if remain > 0 {
        b[0] &= ((1 << remain) - 1)
    }

    return b
}

// [0 0 0 0 0 0]0 0
func LeftMost(b []byte, bits int) []byte {
    bytes := bitsToBytes(bits)
    if len(b) >= bytes {
        b = b[:bytes]
    }

    remain := bits % 8
    if remain > 0 {
        b[0] &= byte(0b_11111111 << (8 - remain))
    }

    return b
}

func incCtr(b []byte) {
    switch len(b) {
        case 1:
            b[0]++
        case 2:
            v := binary.BigEndian.Uint16(b)
            binary.BigEndian.PutUint16(b, v+1)
        case 4:
            v := binary.BigEndian.Uint32(b)
            binary.BigEndian.PutUint32(b, v+1)
        case 8:
            v := binary.BigEndian.Uint64(b)
            binary.BigEndian.PutUint64(b, v+1)
        default:
            for i := len(b) - 1; i >= 0; i-- {
                b[i]++
                if b[i] > 0 {
                    return
                }
            }
    }
}

// ReadBigInt returns a uniform random value in [0, max). It panics if max <= 0.
func ReadBigInt(dst *big.Int, rand io.Reader, buf []byte, max *big.Int) (bufNew []byte, err error) {
    if max.Sign() <= 0 {
        panic("crypto/rand: argument to Int is <= 0")
    }

    dst.Sub(max, dst.SetUint64(1))
    // bitLen is the maximum bit length needed to encode a value < max.
    bitLen := dst.BitLen()
    if bitLen == 0 {
        // the only valid result is 0
        return
    }
    // k is the maximum byte length needed to encode a value < max.
    k := bitsToBytes(bitLen)
    // b is the number of bits in the most significant byte of max-1.
    b := uint(bitLen % 8)
    if b == 0 {
        b = 8
    }

    bufNew = Grow(buf, k)

    mask := uint8(int(1<<b) - 1)

    for {
        _, err = io.ReadFull(rand, bufNew)
        if err != nil {
            return bufNew, err
        }

        // Clear bits in the first byte to increase the probability
        // that the candidate is < max.
        bufNew[0] &= mask

        dst.SetBytes(bufNew)
        if dst.Cmp(max) < 0 {
            return
        }
    }
}

func FermatInverse(k, P *big.Int) *big.Int {
    tmp := new(big.Int).Sub(P, Two)
    return tmp.Exp(k, tmp, P)
}
