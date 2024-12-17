package salsa20

import (
    "errors"
    "crypto/cipher"
    "encoding/binary"

    "golang.org/x/crypto/salsa20/salsa"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type Cipher struct {
    nonce   []byte
    key     [32]byte
    counter uint64
}

// key is 32 bytes, nonce is 16 bytes.
func NewCipher(key, nonce []byte) (cipher.Stream, error) {
    var fixedSizedKey [32]byte
    if len(key) != 32 {
        return nil, errors.New("go-cryptobin/salsa20: key size must be 32")
    }

    copy(fixedSizedKey[:], key)

    return &Cipher{
        key:   fixedSizedKey,
        nonce: nonce,
    }, nil
}

// key is 32 bytes, nonce is 16 bytes.
func NewCipherWithCounter(key, nonce []byte, counter uint64) (cipher.Stream, error) {
    var fixedSizedKey [32]byte
    if len(key) != 32 {
        return nil, errors.New("go-cryptobin/salsa20: key size must be 32")
    }

    copy(fixedSizedKey[:], key)

    return &Cipher{
        key:     fixedSizedKey,
        nonce:   nonce,
        counter: counter,
    }, nil
}

func (c *Cipher) XORKeyStream(dst, src []byte) {
    if len(src) == 0 {
        return
    }
    if len(dst) < len(src) {
        panic("go-cryptobin/salsa20: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/salsa20: invalid buffer overlap")
    }

    paddingLength := int(c.counter % 64)
    buf := make([]byte, len(src)+paddingLength)

    var subNonce [16]byte
    copy(subNonce[:], c.nonce)
    binary.LittleEndian.PutUint64(subNonce[8:], c.counter/64)

    copy(buf[paddingLength:], src)
    salsa.XORKeyStream(buf, buf, &subNonce, &c.key)
    copy(dst, buf[paddingLength:])

    c.counter += uint64(len(src))
}
