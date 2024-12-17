package sm4

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

// BlockSize the sm4 block size in bytes.
const BlockSize = 16

const KeySchedule = 32

// error for key size
type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/sm4: invalid key size " + strconv.Itoa(int(k))
}

type sm4Cipher struct {
    rk [KeySchedule]uint32
}

// NewCipher creates and returns a new cipher.Block.
// key is 16 bytes, so 32 bytes is used half bytes.
// so the cipher use 16 bytes key.
// key bytes and src bytes is BigEndian type.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(sm4Cipher)
    c.expandKey(key)

    return c, nil
}

func (this *sm4Cipher) BlockSize() int {
    return BlockSize
}

func (this *sm4Cipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/sm4: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/sm4: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/sm4: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *sm4Cipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/sm4: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/sm4: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/sm4: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *sm4Cipher) encrypt(dst, src []byte) {
    pt := bytesToUint32s(src)

    /*
     * Uses byte-wise sbox in the first and last rounds to provide some
     * protection from cache based side channels.
     */
    for i := 0; i < 32; i += 4 {
        if i == 0 || i == 28 {
            this.rnds(pt, i, i+1, i+2, i+3, tSlow)
        } else {
            this.rnds(pt, i, i+1, i+2, i+3, t)
        }
    }

    putu32(dst, pt[3])
    putu32(dst[4:], pt[2])
    putu32(dst[8:], pt[1])
    putu32(dst[12:], pt[0])
}

func (this *sm4Cipher) decrypt(dst, src []byte) {
    ct := bytesToUint32s(src)

    for i := 32; i > 0; i -= 4 {
        if i == 32 || i == 4 {
            this.rnds(ct, i-1, i-2, i-3, i-4, tSlow)
        } else {
            this.rnds(ct, i-1, i-2, i-3, i-4, t)
        }
    }

    putu32(dst, ct[3])
    putu32(dst[4:], ct[2])
    putu32(dst[8:], ct[1])
    putu32(dst[12:], ct[0])
}

func (this *sm4Cipher) rnds(b []uint32, k0, k1, k2, k3 int, fn func(uint32) uint32) {
    b[0] ^= fn(b[1] ^ b[2] ^ b[3] ^ this.rk[k0])
    b[1] ^= fn(b[2] ^ b[3] ^ b[0] ^ this.rk[k1])
    b[2] ^= fn(b[3] ^ b[0] ^ b[1] ^ this.rk[k2])
    b[3] ^= fn(b[0] ^ b[1] ^ b[2] ^ this.rk[k3])
}

func (this *sm4Cipher) expandKey(key []byte) {
    var k [4]uint32
    var i int32

    keys := bytesToUint32s(key)
    for i = 0; i < 4; i++ {
        k[i] = keys[i] ^ fk[i]
    }

    for i = 0; i < KeySchedule; i = i + 4 {
        k[0] ^= keySub(k[1] ^ k[2] ^ k[3] ^ ck[i    ])
        k[1] ^= keySub(k[2] ^ k[3] ^ k[0] ^ ck[i + 1])
        k[2] ^= keySub(k[3] ^ k[0] ^ k[1] ^ ck[i + 2])
        k[3] ^= keySub(k[0] ^ k[1] ^ k[2] ^ ck[i + 3])

        copy(this.rk[i:], k[:])
    }
}
