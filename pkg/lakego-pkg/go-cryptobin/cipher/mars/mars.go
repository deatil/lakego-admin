package mars

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/mars: invalid key size " + strconv.Itoa(int(k))
}

type marsCipher struct {
    key [40]uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    keyLen := len(key)

    // MARS has a variable key size from 128 to 448 bits in 32-bit increments
    if keyLen < 16 || keyLen > 56 || (keyLen % 4) != 0 {
        return nil, KeySizeError(keyLen)
    }

    c := new(marsCipher)
    c.expandKey(key)

    return c, nil
}

func (this *marsCipher) BlockSize() int {
    return BlockSize
}

func (this *marsCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/mars: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/mars: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/mars: invalid buffer overlap")
    }

    this.encryptBlock(dst, src)
}

func (this *marsCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/mars: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/mars: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/mars: invalid buffer overlap")
    }

    this.decryptBlock(dst, src)
}

func (this *marsCipher) expandKey(key []byte) {
    var i uint
    var j uint
    var n uint

    var m uint32
    var p uint32
    var r uint32
    var w uint32
    var t1 uint32
    var t2 uint32

    var t [15]uint32

    keyLen := len(key)

    // Determine the number of 32-bit words in the key
    n = uint(keyLen) / 4

    // Initialize T with the original key data
    for i = 0; i < n; i++ {
        t[i] = bytesToUint32(key[4 * i:])
    }

    // Let T[n] = n
    t[i] = uint32(n)
    i++

    // Let T[n+1 ... 14] = 0
    for i < 15 {
        t[i] = 0
        i++
    }

    // Compute 10 words of K in each iteration
    for j = 0; j < 4; j++ {
        // Save T[i-2] and T[i-1]
        t1 = t[13]
        t2 = t[14]

        // Linear key-word expansion
        for i = 0; i < 15; i++ {
            t1 ^= t[(i + 8) % 15]
            t[i] ^= ROL32(t1, 3) ^ uint32(4 * i + j)
            t1 = t2
            t2 = t[i]
        }

        // Repeat 4 rounds of stirring
        for n = 0; n < 4; n++ {
            // Save T[i-1]
            t1 = t[14]

            //S-box based stirring of key-words
            for i = 0; i < 15; i++ {
                t1 = t[i] + S(t1)
                t[i] = ROL32(t1, 9)
                t1 = t[i]
            }
        }

        // Store next 10 key words into K
        for i = 0; i < 10; i++ {
            this.key[10 * j + i] = t[(4 * i) % 15]
        }
    }

    // Modifying multiplication key-words
    for i = 5; i < 37; i += 2 {
        // Let j be the least two bits of K[i]
        j = uint(this.key[i] & 0x03)
        // Let w = K[i] with both of the lowest two bits set to 1
        w = uint32(this.key[i] | 0x03)

        //Generate the word mask M
        MASK_GEN(&m, w)

        //Let r be the least five bits of K[i-1]
        r = this.key[i - 1] & 0x1F

        //Calculate p = B[j] <<< r
        p = ROL32(btab[j], r)

        //Calculate K[i] = w xor (p and M)
        this.key[i] = w ^ (p & m)
    }
}

func (this *marsCipher) encryptBlock(output []byte, input []byte){
    var a uint32
    var b uint32
    var c uint32
    var d uint32

    // The 16 bytes of plaintext are split into 4 words
    a = bytesToUint32(input[0:])
    b = bytesToUint32(input[4:])
    c = bytesToUint32(input[8:])
    d = bytesToUint32(input[12:])

    // Compute (A,B,C,D) = (A,B,C,D) + (K[0],K[1],K[2],K[3])
    a += this.key[0]
    b += this.key[1]
    c += this.key[2]
    d += this.key[3]

    //Forward mixing (8 rounds)
    F_MIX(&a, &b, &c, &d)
    a += d
    F_MIX(&b, &c, &d, &a)
    b += c
    F_MIX(&c, &d, &a, &b)
    F_MIX(&d, &a, &b, &c)
    F_MIX(&a, &b, &c, &d)
    a += d;
    F_MIX(&b, &c, &d, &a);
    b += c
    F_MIX(&c, &d, &a, &b)
    F_MIX(&d, &a, &b, &c)

    //Cryptographic core (16 rounds)
    CORE(&a, &b, &c, &d, this.key[4], this.key[5])
    CORE(&b, &c, &d, &a, this.key[6], this.key[7])
    CORE(&c, &d, &a, &b, this.key[8], this.key[9])
    CORE(&d, &a, &b, &c, this.key[10], this.key[11])
    CORE(&a, &b, &c, &d, this.key[12], this.key[13])
    CORE(&b, &c, &d, &a, this.key[14], this.key[15])
    CORE(&c, &d, &a, &b, this.key[16], this.key[17])
    CORE(&d, &a, &b, &c, this.key[18], this.key[19])
    CORE(&a, &d, &c, &b, this.key[20], this.key[21])
    CORE(&b, &a, &d, &c, this.key[22], this.key[23])
    CORE(&c, &b, &a, &d, this.key[24], this.key[25])
    CORE(&d, &c, &b, &a, this.key[26], this.key[27])
    CORE(&a, &d, &c, &b, this.key[28], this.key[29])
    CORE(&b, &a, &d, &c, this.key[30], this.key[31])
    CORE(&c, &b, &a, &d, this.key[32], this.key[33])
    CORE(&d, &c, &b, &a, this.key[34], this.key[35])

    // Backwards mixing (8 rounds)
    B_MIX(&a, &b, &c, &d)
    B_MIX(&b, &c, &d, &a)
    c -= b;
    B_MIX(&c, &d, &a, &b)
    d -= a;
    B_MIX(&d, &a, &b, &c)
    B_MIX(&a, &b, &c, &d)
    B_MIX(&b, &c, &d, &a)
    c -= b;
    B_MIX(&c, &d, &a, &b)
    d -= a;
    B_MIX(&d, &a, &b, &c)

    //Compute (A,B,C,D) = (A,B,C,D) - (K[36],K[37],K[38],K[39])
    a -= this.key[36]
    b -= this.key[37]
    c -= this.key[38]
    d -= this.key[39]

    // The 4 words of ciphertext are then written as 16 bytes
    aBytes := uint32ToBytes(a)
    bBytes := uint32ToBytes(b)
    cBytes := uint32ToBytes(c)
    dBytes := uint32ToBytes(d)

    copy(output[0:], aBytes[:])
    copy(output[4:], bBytes[:])
    copy(output[8:], cBytes[:])
    copy(output[12:], dBytes[:])
}

func (this *marsCipher) decryptBlock(output []byte, input []byte) {
    var d uint32
    var c uint32
    var b uint32
    var a uint32

    // The 16 bytes of ciphertext are split into 4 words
    a = bytesToUint32(input[0:])
    b = bytesToUint32(input[4:])
    c = bytesToUint32(input[8:])
    d = bytesToUint32(input[12:])

    //Compute (A,B,C,D) = (A,B,C,D) + (K[36],K[37],K[38],K[39])
    a += this.key[36]
    b += this.key[37]
    c += this.key[38]
    d += this.key[39]

    //Forward mixing (8 rounds)
    F_MIX(&d, &c, &b, &a)
    d += a
    F_MIX(&c, &b, &a, &d)
    c += b
    F_MIX(&b, &a, &d, &c)
    F_MIX(&a, &d, &c, &b)
    F_MIX(&d, &c, &b, &a)
    d += a
    F_MIX(&c, &b, &a, &d)
    c += b
    F_MIX(&b, &a, &d, &c)
    F_MIX(&a, &d, &c, &b)

    //Cryptographic core (16 rounds)
    CORE_INV(&d, &c, &b, &a, this.key[34], this.key[35])
    CORE_INV(&c, &b, &a, &d, this.key[32], this.key[33])
    CORE_INV(&b, &a, &d, &c, this.key[30], this.key[31])
    CORE_INV(&a, &d, &c, &b, this.key[28], this.key[29])
    CORE_INV(&d, &c, &b, &a, this.key[26], this.key[27])
    CORE_INV(&c, &b, &a, &d, this.key[24], this.key[25])
    CORE_INV(&b, &a, &d, &c, this.key[22], this.key[23])
    CORE_INV(&a, &d, &c, &b, this.key[20], this.key[21])
    CORE_INV(&d, &a, &b, &c, this.key[18], this.key[19])
    CORE_INV(&c, &d, &a, &b, this.key[16], this.key[17])
    CORE_INV(&b, &c, &d, &a, this.key[14], this.key[15])
    CORE_INV(&a, &b, &c, &d, this.key[12], this.key[13])
    CORE_INV(&d, &a, &b, &c, this.key[10], this.key[11])
    CORE_INV(&c, &d, &a, &b, this.key[8], this.key[9])
    CORE_INV(&b, &c, &d, &a, this.key[6], this.key[7])
    CORE_INV(&a, &b, &c, &d, this.key[4], this.key[5])

    //Backwards mixing (8 rounds)
    B_MIX(&d, &c, &b, &a)
    B_MIX(&c, &b, &a, &d)
    b -= c
    B_MIX(&b, &a, &d, &c)
    a -= d
    B_MIX(&a, &d, &c, &b)
    B_MIX(&d, &c, &b, &a)
    B_MIX(&c, &b, &a, &d)
    b -= c
    B_MIX(&b, &a, &d, &c)
    a -= d
    B_MIX(&a, &d, &c, &b)

    //Compute (A,B,C,D) = (A,B,C,D) - (K[0],K[1],K[2],K[3])
    a -= this.key[0]
    b -= this.key[1]
    c -= this.key[2]
    d -= this.key[3]

    //The 4 words of plaintext are then written as 16 bytes
    aBytes := uint32ToBytes(a)
    bBytes := uint32ToBytes(b)
    cBytes := uint32ToBytes(c)
    dBytes := uint32ToBytes(d)

    copy(output[0:], aBytes[:])
    copy(output[4:], bBytes[:])
    copy(output[8:], cBytes[:])
    copy(output[12:], dBytes[:])
}
