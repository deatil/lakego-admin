package enigma

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const ROTORSZ int32 = 256
const MASK uint32 = 0377

const DefaultSeed int32 = 123

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/enigma: invalid key size " + strconv.Itoa(int(k))
}

type enigmaCipher struct {
    seed int32

    t1 [ROTORSZ]int8
    t2 [ROTORSZ]int8
    t3 [ROTORSZ]int8
    deck [ROTORSZ]int8
    cbuf [13]int8
    n1, n2, nr1, nr2 int32
}

// NewCipher creates and returns a new cipher.Stream.
func NewCipher(key []byte) (cipher.Stream, error) {
    return NewCipherWithSeed(key, DefaultSeed)
}

// NewCipherWithSeed creates and returns a new cipher.Stream.
func NewCipherWithSeed(key []byte, seed int32) (cipher.Stream, error) {
    k := len(key)
    switch k {
        case 13:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(enigmaCipher)
    c.seed = seed
    c.expandKey(key)

    return c, nil
}

func (this *enigmaCipher) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("go-cryptobin/enigma: output not full block")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/enigma: invalid buffer overlap")
    }

    var i int32
    var secureflg int32 = 0

    var ciphertext []byte = make([]byte, len(src))

    copy(ciphertext, src)

    var kk int32

    for j := 0; j < len(ciphertext); j++ {
        i = int32(ciphertext[j])

        if secureflg == 1 {
            this.nr1 = int32(uint32(this.deck[this.n1]) & MASK)
            this.nr2 = int32(uint32(this.deck[this.nr1]) & MASK)
        } else {
            this.nr1 = this.n1
        }

        kk = int32(this.t1[int32(uint32(i + this.nr1) & MASK)])
        kk = int32(this.t3[int32(uint32(kk + this.nr2) & MASK)])
        kk = int32(this.t2[int32(uint32(kk - this.nr2) & MASK)])

        i = kk - this.nr1

        ciphertext[j] = byte(i)

        this.n1++

        if this.n1 == ROTORSZ {
            this.n1 = 0
            this.n2++

            if this.n2 == ROTORSZ {
                this.n2 = 0;
            }

            if secureflg == 1 {
                this.shuffle()
            } else {
                this.nr2 = this.n2
            }
        }
    }

    copy(dst, ciphertext)
}

func (this *enigmaCipher) expandKey(key []byte) {
    var ic, i, k, temp int32
    var random uint32
    var seed int32

    this.n1 = 0
    this.n2 = 0
    this.nr1 = 0
    this.nr2 = 0

    for ik, vk := range key {
        this.cbuf[ik] = int8(vk)
    }

    seed = this.seed
    for i = 0; i < 13; i++ {
        seed = seed * int32(this.cbuf[i]) + i;
    }

    for i = 0; i < ROTORSZ; i++ {
        this.t1[i] = int8(i)
        this.deck[i] = int8(i)
    }

    for i = 0; i < ROTORSZ; i++ {
        seed = 5 * seed + int32(this.cbuf[i % 13])
        random = uint32(seed % 65521)

        k = ROTORSZ - 1 - i
        ic = int32((random & MASK) % uint32(k + 1))

        random >>= 8

        temp = int32(this.t1[k])
        this.t1[k] = this.t1[ic]
        this.t1[ic] = int8(temp)

        if this.t3[k] != 0 {
            continue
        }

        ic = int32((random & MASK) % uint32(k))
        for this.t3[ic] != 0 {
            ic = (ic + 1) % k
        }

        this.t3[k] = int8(ic)
        this.t3[ic] = int8(k)
    }

    for i = 0; i < ROTORSZ; i++ {
        this.t2[int32(uint32(this.t1[i]) & MASK)] = int8(i)
    }
}

func (this *enigmaCipher) shuffle() {
    var i, ic, k, temp int32
    var random uint32
    var seed int32 = this.seed

    for i = 0; i < ROTORSZ; i++ {
        seed = 5 * seed + int32(this.cbuf[i % 13])
        random = uint32(seed % 65521)

        k = ROTORSZ - 1 - i
        ic = int32((random & MASK) % uint32(k + 1))

        temp = int32(this.deck[k])
        this.deck[k] = this.deck[ic]
        this.deck[ic] = int8(temp)
    }
}
