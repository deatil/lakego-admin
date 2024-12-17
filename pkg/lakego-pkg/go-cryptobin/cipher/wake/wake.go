package wake

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

// WAKE reference C-code, based on the description in David J. Wheeler's
// paper "A bulk Data Encryption Algorithm"

const BlockSize = 1

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/wake: invalid key size " + strconv.Itoa(int(k))
}

type wakeCipher struct {
    t [257]uint32
    r [4]uint32
    counter int32
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
            return nil, KeySizeError(k)
    }

    c := new(wakeCipher)
    c.expandKey(key)

    return c, nil
}

func (this *wakeCipher) BlockSize() int {
    return BlockSize
}

func (this *wakeCipher) Encrypt(dst, src []byte) {
    if len(dst) < len(src) {
        panic("go-cryptobin/wake: output not full block")
    }

    bs := len(src)

    if alias.InexactOverlap(dst[:bs], src[:bs]) {
        panic("go-cryptobin/wake: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *wakeCipher) Decrypt(dst, src []byte) {
    if len(dst) < len(src) {
        panic("go-cryptobin/wake: output not full block")
    }

    bs := len(src)

    if alias.InexactOverlap(dst[:bs], src[:bs]) {
        panic("go-cryptobin/wake: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *wakeCipher) encrypt(dst, src []byte) {
    var r2, r3, r4, r5 uint32
    var r6 uint32
    var i int32

    input := make([]byte, len(src))
    copy(input, src)

    r3 = this.r[0]
    r4 = this.r[1]
    r5 = this.r[2]
    r6 = this.r[3]

    for i = 0; i < int32(len(input)); i++ {
        /* R1 = V[n] = V[n] XOR R6 - here we do it per byte --sloooow */
        /* R1 is ignored */
        r6Bytes := uint32ToBytes(r6)
        input[i] ^= r6Bytes[this.counter]

        /* R2 = V[n] = R1 - per byte also */
        r2Bytes := uint32ToBytes(r2)
        r2Bytes[this.counter] = input[i]
        r2 = bytesToUint32(r2Bytes[:])

        this.counter++

        if (this.counter == 4) { /* r6 was used - update it! */
            this.counter = 0

            /* these swaps are because we do operations per byte */
            r3 = this.M(r3, r2)
            r4 = this.M(r4, r3)
            r5 = this.M(r5, r4)
            r6 = this.M(r6, r5)
        }
    }

    this.r[0] = r3
    this.r[1] = r4
    this.r[2] = r5
    this.r[3] = r6

    copy(dst, input)
}

func (this *wakeCipher) decrypt(dst, src []byte) {
    var r1, r3, r4, r5 uint32
    var r6 uint32
    var i int32

    input := make([]byte, len(src))
    copy(input, src)

    r3 = this.r[0]
    r4 = this.r[1]
    r5 = this.r[2]
    r6 = this.r[3]

    for i = 0; i < int32(len(input)); i++ {
        /* R1 = V[n] */
        r1Bytes := uint32ToBytes(r1)
        r1Bytes[this.counter] = input[i]
        r1 = bytesToUint32(r1Bytes[:])

        /* R2 = V[n] = V[n] ^ R6 */
        /* R2 is ignored */
        r6Bytes := uint32ToBytes(r6)
        input[i] ^= r6Bytes[this.counter]

        this.counter++

        if (this.counter == 4) {
            this.counter = 0

            r3 = this.M(r3, r1)
            r4 = this.M(r4, r3)
            r5 = this.M(r5, r4)
            r6 = this.M(r6, r5)
        }
    }

    this.r[0] = r3
    this.r[1] = r4
    this.r[2] = r5
    this.r[3] = r6

    copy(dst, input)
}

var tt = [10]uint32{
    0x726a8f3b,
    0xe69a3b5c,
    0xd3c71fe5,
    0xab3c73d2,
    0x4d3a8eb3,
    0x0396d6e8,
    0x3d4c2f7a,
    0x9ee27cf3,
}

func (this *wakeCipher) expandKey(inkey []byte) {
    var x, z, p uint32
    var k [4]uint32

    key := bytesToUint32s(inkey)

    k[0] = key[0]
    k[1] = key[1]
    k[2] = key[2]
    k[3] = key[3]

    for p = 0; p < 4; p++ {
        this.t[p] = k[p]
    }

    for p = 4; p < 256; p++ {
        x = this.t[p - 4] + this.t[p - 1]
        this.t[p] = x >> 3 ^ tt[x & 7]
    }

    for p = 0; p < 23; p++ {
        this.t[p] += this.t[p + 89]
    }

    x = this.t[33]
    z = this.t[59] | 0x01000001
    z &= 0xff7fffff

    for p = 0; p < 256; p++ {
        x = (x & 0xff7fffff) + z
        this.t[p] = (this.t[p] & 0x00ffffff) ^ x
    }

    this.t[256] = this.t[0]
    x &= 0xff

    for p = 0; p < 256; p++ {
        x = (this.t[p ^ x] ^ x) & 0xff

        this.t[p] = this.t[x]
        this.t[x] = this.t[p + 1]
    }

    this.counter = 0;

    this.r[0] = k[0]
    this.r[1] = k[1]
    this.r[2] = k[2]
    this.r[3] = k[3]
}

func (this *wakeCipher) M(X uint32, Y uint32) uint32 {
    var TMP uint32

    TMP = X + Y;

    return (((TMP >> 8) & 0x00ffffff) ^ this.t[TMP & 0xff])
}
