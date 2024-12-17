package safer

import (
    "errors"
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 8

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/safer: invalid key size " + strconv.Itoa(int(k))
}

type saferCipher struct {
    key []uint8
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte, rounds int32) (cipher.Block, error) {
    return NewSKCipher(key, rounds)
}

// NewKCipher creates and returns a new cipher.Block.
func NewKCipher(key []byte, rounds int32) (cipher.Block, error) {
    c := new(saferCipher)
    c.key = make([]uint8, SAFER_KEY_LEN)

    k := len(key)
    switch k {
        case 8:
            c.setK64Key(key, int32(k), rounds)
            return c, nil
        case 16:
            c.setK128Key(key, int32(k), rounds)
            return c, nil
    }

    return nil, KeySizeError(k)
}

// NewSKCipher creates and returns a new cipher.Block.
func NewSKCipher(key []byte, rounds int32) (cipher.Block, error) {
    c := new(saferCipher)
    c.key = make([]uint8, SAFER_KEY_LEN)

    k := len(key)
    switch k {
        case 8:
            c.setSK64Key(key, int32(k), rounds)
            return c, nil
        case 16:
            c.setSK128Key(key, int32(k), rounds)
            return c, nil
    }

    return nil, KeySizeError(k)
}

func (this *saferCipher) BlockSize() int {
    return BlockSize
}

func (this *saferCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/safer: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/safer: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/safer: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *saferCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/safer: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/safer: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/safer: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *saferCipher) encrypt(block_out, block_in []byte) {
    var a, b, c, d, e, f, g, h, t uint8
    var round uint32
    var key []uint8

    key = this.key[:]

    a = block_in[0]
    b = block_in[1]
    c = block_in[2]
    d = block_in[3]
    e = block_in[4]
    f = block_in[5]
    g = block_in[6]
    h = block_in[7]

    round = uint32(key[0])
    if SAFER_MAX_NOF_ROUNDS < round {
        round = SAFER_MAX_NOF_ROUNDS;
    }

    var ii uint32
    var ki uint32

    for ii = round; ii > 0; ii-- {
        ki++
        a ^= key[ki]
        ki++
        b += key[ki]
        ki++
        c += key[ki]
        ki++
        d ^= key[ki]
        ki++
        e ^= key[ki]
        ki++
        f += key[ki]
        ki++
        g += key[ki]
        ki++
        h ^= key[ki]

        ki++
        a = EXP(a) + key[ki]
        ki++
        b = LOG(b) ^ key[ki]
        ki++
        c = LOG(c) ^ key[ki]
        ki++
        d = EXP(d) + key[ki]
        ki++
        e = EXP(e) + key[ki]
        ki++
        f = LOG(f) ^ key[ki]
        ki++
        g = LOG(g) ^ key[ki]
        ki++
        h = EXP(h) + key[ki]

        PHT(&a, &b)
        PHT(&c, &d)
        PHT(&e, &f)
        PHT(&g, &h)
        PHT(&a, &c)
        PHT(&e, &g)
        PHT(&b, &d)
        PHT(&f, &h)
        PHT(&a, &e)
        PHT(&b, &f)
        PHT(&c, &g)
        PHT(&d, &h)

        t = b
        b = e
        e = c
        c = t
        t = d
        d = f
        f = g
        g = t
    }

    ki++
    a ^= key[ki]
    ki++
    b += key[ki]
    ki++
    c += key[ki]
    ki++
    d ^= key[ki]
    ki++
    e ^= key[ki]
    ki++
    f += key[ki]
    ki++
    g += key[ki]
    ki++
    h ^= key[ki]

    block_out[0] = a & 0xFF
    block_out[1] = b & 0xFF
    block_out[2] = c & 0xFF
    block_out[3] = d & 0xFF
    block_out[4] = e & 0xFF
    block_out[5] = f & 0xFF
    block_out[6] = g & 0xFF
    block_out[7] = h & 0xFF
}

func (this *saferCipher) decrypt(block_out, block_in []byte) {
    var a, b, c, d, e, f, g, h, t uint8
    var round uint32
    var key []uint8

    key = this.key[:]

    a = block_in[0]
    b = block_in[1]
    c = block_in[2]
    d = block_in[3]
    e = block_in[4]
    f = block_in[5]
    g = block_in[6]
    h = block_in[7]

    round = uint32(key[0])
    if SAFER_MAX_NOF_ROUNDS < round {
        round = SAFER_MAX_NOF_ROUNDS;
    }

    var ii uint32
    var ki uint32

    ki = SAFER_BLOCK_LEN * (1 + 2 * round)

    h ^= key[ki]
    ki--
    g -= key[ki]
    ki--
    f -= key[ki]
    ki--
    e ^= key[ki]
    ki--
    d ^= key[ki]
    ki--
    c -= key[ki]
    ki--
    b -= key[ki]
    ki--
    a ^= key[ki]

    for ii = round; ii > 0; ii-- {
        t = e
        e = b
        b = c
        c = t
        t = f
        f = d
        d = g
        g = t

        IPHT(&a, &e)
        IPHT(&b, &f)
        IPHT(&c, &g)
        IPHT(&d, &h)
        IPHT(&a, &c)
        IPHT(&e, &g)
        IPHT(&b, &d)
        IPHT(&f, &h)
        IPHT(&a, &b)
        IPHT(&c, &d)
        IPHT(&e, &f)
        IPHT(&g, &h)

        ki--
        h -= key[ki]
        ki--
        g ^= key[ki]
        ki--
        f ^= key[ki]
        ki--
        e -= key[ki]
        ki--
        d -= key[ki]
        ki--
        c ^= key[ki]
        ki--
        b ^= key[ki]
        ki--
        a -= key[ki]

        ki--
        h = LOG(h) ^ key[ki]
        ki--
        g = EXP(g) - key[ki]
        ki--
        f = EXP(f) - key[ki]
        ki--
        e = LOG(e) ^ key[ki]
        ki--
        d = LOG(d) ^ key[ki]
        ki--
        c = EXP(c) - key[ki]
        ki--
        b = EXP(b) - key[ki]
        ki--
        a = LOG(a) ^ key[ki]
    }

    block_out[0] = a & 0xFF;
    block_out[1] = b & 0xFF;
    block_out[2] = c & 0xFF;
    block_out[3] = d & 0xFF;
    block_out[4] = e & 0xFF;
    block_out[5] = f & 0xFF;
    block_out[6] = g & 0xFF;
    block_out[7] = h & 0xFF;
}

func (this *saferCipher) setK64Key(key []uint8, keylen int32, numrounds int32) error {
    if numrounds != 0 && (numrounds < 6 || numrounds > SAFER_MAX_NOF_ROUNDS) {
        return errors.New("go-cryptobin/safer: invalid numrounds")
    }

    if (keylen != 8) {
        return errors.New("go-cryptobin/safer: invalid keysize")
    }

    var rounds int32

    if numrounds != 0 {
        rounds = numrounds
    } else {
        rounds = SAFER_K64_DEFAULT_NOF_ROUNDS
    }

    Safer_Expand_Userkey(key, key, uint32(rounds), 0, this.key)

    return nil
}

func (this *saferCipher) setK128Key(key []uint8, keylen int32, numrounds int32) error {
    if numrounds != 0 && (numrounds < 6 || numrounds > SAFER_MAX_NOF_ROUNDS) {
        return errors.New("go-cryptobin/safer: invalid numrounds")
    }

    if (keylen != 16) {
        return errors.New("go-cryptobin/safer: invalid keysize")
    }

    var rounds int32

    if numrounds != 0 {
        rounds = numrounds
    } else {
        rounds = SAFER_K128_DEFAULT_NOF_ROUNDS
    }

    Safer_Expand_Userkey(key, key[8:], uint32(rounds), 0, this.key)

    return nil
}

func (this *saferCipher) setSK64Key(key []uint8, keylen int32, numrounds int32) error {
    if numrounds != 0 && (numrounds < 6 || numrounds > SAFER_MAX_NOF_ROUNDS) {
        return errors.New("go-cryptobin/safer: invalid numrounds")
    }

    if (keylen != 8) {
        return errors.New("go-cryptobin/safer: invalid keysize")
    }

    var rounds int32

    if numrounds != 0 {
        rounds = numrounds
    } else {
        rounds = SAFER_SK64_DEFAULT_NOF_ROUNDS
    }

    Safer_Expand_Userkey(key, key, uint32(rounds), 1, this.key)

    return nil
}

func (this *saferCipher) setSK128Key(key []uint8, keylen int32, numrounds int32) error {
    if numrounds != 0 && (numrounds < 6 || numrounds > SAFER_MAX_NOF_ROUNDS) {
        return errors.New("go-cryptobin/safer: invalid numrounds")
    }

    if (keylen != 16) {
        return errors.New("go-cryptobin/safer: invalid keysize")
    }

    var rounds int32

    if numrounds != 0 {
        rounds = numrounds
    } else {
        rounds = SAFER_SK128_DEFAULT_NOF_ROUNDS
    }

    Safer_Expand_Userkey(key, key[8:], uint32(rounds), 1, this.key)

    return nil
}
