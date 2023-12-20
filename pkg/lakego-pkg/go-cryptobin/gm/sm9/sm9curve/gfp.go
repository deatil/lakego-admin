package sm9curve

import (
    "fmt"
    "math/big"
    "crypto/sha256"
    "encoding/binary"

    "golang.org/x/crypto/hkdf"
)

type gfP [4]uint64

func newGFp(x int64) (out *gfP) {
    if x >= 0 {
        out = &gfP{uint64(x)}
    } else {
        out = &gfP{uint64(-x)}
        gfpNeg(out, out)
    }

    montEncode(out, out)
    return out
}

// hashToBase implements hashing a message to an element of the field.
//
// L = ceil((256+128)/8)=48, ctr = 0, i = 1
func hashToBase(msg, dst []byte) *gfP {
    var t [48]byte
    info := []byte{'H', '2', 'C', byte(0), byte(1)}
    r := hkdf.New(sha256.New, msg, dst, info)
    if _, err := r.Read(t[:]); err != nil {
        panic(err)
    }
    var x big.Int
    v := x.SetBytes(t[:]).Mod(&x, p).Bytes()
    v32 := [32]byte{}
    for i := len(v) - 1; i >= 0; i-- {
        v32[len(v)-1-i] = v[i]
    }
    u := &gfP{
        binary.LittleEndian.Uint64(v32[0*8 : 1*8]),
        binary.LittleEndian.Uint64(v32[1*8 : 2*8]),
        binary.LittleEndian.Uint64(v32[2*8 : 3*8]),
        binary.LittleEndian.Uint64(v32[3*8 : 4*8]),
    }
    montEncode(u, u)
    return u
}

func (e *gfP) String() string {
    return fmt.Sprintf("%16.16x%16.16x%16.16x%16.16x", e[3], e[2], e[1], e[0])
}

func (e *gfP) Set(f *gfP) {
    e[0] = f[0]
    e[1] = f[1]
    e[2] = f[2]
    e[3] = f[3]
}

func (e *gfP) exp(f *gfP, bits [4]uint64) {
    sum, power := &gfP{}, &gfP{}
    sum.Set(rN1)
    power.Set(f)

    for word := 0; word < 4; word++ {
        for bit := uint(0); bit < 64; bit++ {
            if (bits[word]>>bit)&1 == 1 {
                gfpMul(sum, sum, power)
            }
            gfpMul(power, power, power)
        }
    }

    gfpMul(sum, sum, r3)
    e.Set(sum)
}

func (e *gfP) Invert(f *gfP) {
    e.exp(f, pMinus2)
}

func (e *gfP) Sqrt(f *gfP) {
    // Since p = 8k+5,
    // if f^((k+1)/4) = 1 mod p, then
    // e = f^(k+1) is a root of f;
    //else if f^((k+1)/4) = -1 mod p, then
    //e = 2^(2k+1)*f^(k+1) is a root of f.
    one := newGFp(1)
    tmp := new(gfP)
    tmp.exp(f, pMinus1Over4)

    if *tmp == *one {
        e.exp(f, pPlus3Over4)
    } else if *tmp == pMinus1 {
        e.exp(f, pPlus3Over4)
        gfpMul(e, e, &twoTo2kPlus1)
    }
}

func (e *gfP) Marshal(out []byte) {
    for w := uint(0); w < 4; w++ {
        for b := uint(0); b < 8; b++ {
            out[8*w+b] = byte(e[3-w] >> (56 - 8*b))
        }
    }
}

func (e *gfP) Unmarshal(in []byte) {
    for w := uint(0); w < 4; w++ {
        e[3-w] = 0
        for b := uint(0); b < 8; b++ {
            e[3-w] += uint64(in[8*w+b]) << (56 - 8*b)
        }
    }
}

func montEncode(c, a *gfP) { gfpMul(c, a, r2) }
func montDecode(c, a *gfP) { gfpMul(c, a, &gfP{1}) }

func sign0(e *gfP) int {
    x := &gfP{}
    montDecode(x, e)
    for w := 3; w >= 0; w-- {
        if x[w] > pMinus1Over2[w] {
            return 1
        } else if x[w] < pMinus1Over2[w] {
            return -1
        }
    }
    return 1
}

func legendre(e *gfP) int {
    f := &gfP{}
    // Since p = 8k+5, then e^(4k+2) is the Legendre symbol of e.
    f.exp(e, pMinus1Over2)

    montDecode(f, f)

    if *f != [4]uint64{} {
        return 2*int(f[0]&1) - 1
    }

    return 0
}

func (c *gfP) Println() {
    fmt.Print("&gfP{")
    y, _ := new(big.Int).SetString(c.String(), 16)
    words := y.Bits()
    for _, word := range words[:len(words)-1] {
        fmt.Printf("%#x, ", word)
    }
    fmt.Printf("%#x}\n\n", words[len(words)-1])
}

func gfpFromString(s string) gfP {
    y, _ := new(big.Int).SetString(s, 16)
    words := y.Bits()
    var a = gfP{}
    for i := 0; i < len(words); i++ {
        a[i] = uint64(words[i])
    }
    return a
}
