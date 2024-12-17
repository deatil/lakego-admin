package lion

import (
    "fmt"
    "hash"
    "crypto/cipher"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type Streamer = func([]byte) (cipher.Stream, error)

type lionCipher struct {
    key1 []byte
    key2 []byte

    hash   hash.Hash
    cipher Streamer
    bs     int
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(hash hash.Hash, cipher Streamer, bs int, key []byte) (cipher.Block, error) {
    c := new(lionCipher)
    c.hash = hash
    c.cipher = cipher
    c.bs = mathMax(2 * hash.Size() + 1, bs)

    if 2 * c.leftSize() + 1 > c.bs {
        return nil, fmt.Errorf("Block size %d is too small", c.bs)
    }

    c.expandKey(key)

    return c, nil
}

func (this *lionCipher) BlockSize() int {
    return this.bs
}

func (this *lionCipher) Encrypt(dst, src []byte) {
    bs := this.bs

    if len(src) < bs {
        panic(fmt.Sprintf("go-cryptobin/lion: invalid block size %d (src)", len(src)))
    }

    if len(dst) < bs {
        panic(fmt.Sprintf("go-cryptobin/lion: invalid block size %d (dst)", len(dst)))
    }

    if alias.InexactOverlap(dst[:bs], src[:bs]) {
        panic("go-cryptobin/lion: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *lionCipher) Decrypt(dst, src []byte) {
    bs := this.bs

    if len(src) < bs {
        panic(fmt.Sprintf("go-cryptobin/lion: invalid block size %d (src)", len(src)))
    }

    if len(dst) < bs {
        panic(fmt.Sprintf("go-cryptobin/lion: invalid block size %d (dst)", len(dst)))
    }

    if alias.InexactOverlap(dst[:bs], src[:bs]) {
        panic("go-cryptobin/lion: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *lionCipher) encrypt(dst, src []byte) {
    leftSize := this.leftSize()

    buffer := make([]byte, leftSize)

    subtle.XORBytes(buffer, src[:leftSize], this.key1)
    cip, err := this.cipher(buffer)
    if err != nil {
        panic(err)
    }
    cip.XORKeyStream(dst[leftSize:], src[leftSize:])

    this.hash.Reset()
    this.hash.Write(dst[leftSize:])
    buffer = this.hash.Sum(nil)
    subtle.XORBytes(dst[:leftSize], src[:leftSize], buffer)

    subtle.XORBytes(buffer, dst[:leftSize], this.key2)
    cip, err = this.cipher(buffer)
    if err != nil {
        panic(err)
    }
    cip.XORKeyStream(dst[leftSize:], dst[leftSize:])
}

func (this *lionCipher) decrypt(dst, src []byte) {
    leftSize := this.leftSize()

    buffer := make([]byte, leftSize)

    subtle.XORBytes(buffer, src[:leftSize], this.key2)
    cip, err := this.cipher(buffer)
    if err != nil {
        panic(err)
    }
    cip.XORKeyStream(dst[leftSize:], src[leftSize:])

    this.hash.Reset()
    this.hash.Write(dst[leftSize:])
    buffer = this.hash.Sum(nil)
    subtle.XORBytes(dst[:leftSize], src[:leftSize], buffer)

    subtle.XORBytes(buffer, dst[:leftSize], this.key1)
    cip, err = this.cipher(buffer)
    if err != nil {
        panic(err)
    }
    cip.XORKeyStream(dst[leftSize:], dst[leftSize:])
}

func (this *lionCipher) expandKey(key []byte) {
    half := len(key) / 2

    this.key1 = make([]byte, this.leftSize())
    this.key2 = make([]byte, this.leftSize())

    copy(this.key1, key[:half])
    copy(this.key2, key[half:])
}

func (this *lionCipher) leftSize() int {
    return this.hash.Size()
}

func (this *lionCipher) rightSize() int {
    return this.bs - this.leftSize()
}

func mathMax(a, b int) int {
    if a > b {
        return a
    }

    return b
}
