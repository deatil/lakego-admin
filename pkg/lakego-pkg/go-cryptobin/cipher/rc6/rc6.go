package rc6

import (
    "strconv"
    "math/bits"
    "crypto/cipher"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool/alias"
)

// For more information, please see:
//  https://en.wikipedia.org/wiki/RC6
//  http://www.emc.com/emc-plus/rsa-labs/historical/rc6-block-cipher.htm

const (
    BlockSize = 16
    keyWords  = 4
    rounds    = 20
    roundKeys = 2*rounds + 4
)

var skeytable = []uint32{
    0xb7e15163, 0x5618cb1c, 0xf45044d5, 0x9287be8e, 0x30bf3847, 0xcef6b200, 0x6d2e2bb9, 0x0b65a572,
    0xa99d1f2b, 0x47d498e4, 0xe60c129d, 0x84438c56, 0x227b060f, 0xc0b27fc8, 0x5ee9f981, 0xfd21733a,
    0x9b58ecf3, 0x399066ac, 0xd7c7e065, 0x75ff5a1e, 0x1436d3d7, 0xb26e4d90, 0x50a5c749, 0xeedd4102,
    0x8d14babb, 0x2b4c3474, 0xc983ae2d, 0x67bb27e6, 0x05f2a19f, 0xa42a1b58, 0x42619511, 0xe0990eca,
    0x7ed08883, 0x1d08023c, 0xbb3f7bf5, 0x5976f5ae, 0xf7ae6f67, 0x95e5e920, 0x341d62d9, 0xd254dc92,
    0x708c564b, 0x0ec3d004, 0xacfb49bd, 0x4b32c376,
}

// KeySizeError
type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/rc6: invalid key size " + strconv.Itoa(int(k))
}

type rc6Cipher struct {
    rk [roundKeys]uint32
}

// New returns a cipher.Block implementing RC6.
// The key argument must be 16 bytes.
func NewCipher(key []byte) (cipher.Block, error) {
    if l := len(key); l != 16 {
        return nil, KeySizeError(l)
    }

    c := new(rc6Cipher)
    c.expandKey(key)

    return c, nil
}

func (c *rc6Cipher) BlockSize() int {
    return BlockSize
}

func (c *rc6Cipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/rc6: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/rc6: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/rc6: invalid buffer overlap")
    }

    c.encrypt(dst, src)
}

func (c *rc6Cipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/rc6: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/rc6: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/rc6: invalid buffer overlap")
    }

    c.decrypt(dst, src)
}

func (c *rc6Cipher) expandKey(key []byte) {
    var L [keyWords]uint32

    for i := 0; i < keyWords; i++ {
        L[i] = binary.LittleEndian.Uint32(key[:4])
        key = key[4:]
    }

    copy(c.rk[:], skeytable)

    var A uint32
    var B uint32
    var i, j int

    for k := 0; k < 3*roundKeys; k++ {
        c.rk[i] = bits.RotateLeft32(c.rk[i]+(A+B), 3)
        A = c.rk[i]
        L[j] = bits.RotateLeft32(L[j]+(A+B), int(A+B))
        B = L[j]

        i = (i + 1) % roundKeys
        j = (j + 1) % keyWords
    }
}

func (c *rc6Cipher) encrypt(dst, src []byte) {
    A := binary.LittleEndian.Uint32(src[:4])
    B := binary.LittleEndian.Uint32(src[4:8])
    C := binary.LittleEndian.Uint32(src[8:12])
    D := binary.LittleEndian.Uint32(src[12:16])

    B = B + c.rk[0]
    D = D + c.rk[1]
    for i := 1; i <= rounds; i++ {
        t := bits.RotateLeft32(B*(2*B+1), 5)
        u := bits.RotateLeft32(D*(2*D+1), 5)
        A = bits.RotateLeft32((A^t), int(u)) + c.rk[2*i]
        C = bits.RotateLeft32((C^u), int(t)) + c.rk[2*i+1]
        A, B, C, D = B, C, D, A
    }

    A = A + c.rk[2*rounds+2]
    C = C + c.rk[2*rounds+3]

    binary.LittleEndian.PutUint32(dst[:4], A)
    binary.LittleEndian.PutUint32(dst[4:8], B)
    binary.LittleEndian.PutUint32(dst[8:12], C)
    binary.LittleEndian.PutUint32(dst[12:16], D)
}

func (c *rc6Cipher) decrypt(dst, src []byte) {
    A := binary.LittleEndian.Uint32(src[:4])
    B := binary.LittleEndian.Uint32(src[4:8])
    C := binary.LittleEndian.Uint32(src[8:12])
    D := binary.LittleEndian.Uint32(src[12:16])

    C = C - c.rk[2*rounds+3]
    A = A - c.rk[2*rounds+2]

    for i := rounds; i >= 1; i-- {
        A, B, C, D = D, A, B, C
        u := bits.RotateLeft32(D*(2*D+1), 5)
        t := bits.RotateLeft32(B*(2*B+1), 5)
        C = bits.RotateLeft32((C-c.rk[2*i+1]), -int(t)) ^ u
        A = bits.RotateLeft32((A-c.rk[2*i]), -int(u)) ^ t
    }

    D = D - c.rk[1]
    B = B - c.rk[0]

    binary.LittleEndian.PutUint32(dst[:4], A)
    binary.LittleEndian.PutUint32(dst[4:8], B)
    binary.LittleEndian.PutUint32(dst[8:12], C)
    binary.LittleEndian.PutUint32(dst[12:16], D)
}
