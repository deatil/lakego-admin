package grain

import (
    "errors"
    "crypto/cipher"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const (
    // BlockSize is the size in bytes of an Grain128-AEAD block.
    BlockSize = 16
    // KeySize is the size in bytes of an Grain128-AEAD key.
    KeySize = 16
    // NonceSize is the size in bytes of an Grain128-AEAD nonce.
    NonceSize = 12
    // TagSize is the size in bytes of an Grain128-AEAD
    // authenticator.
    TagSize = 8
)

// stream implements cipher.Stream.
type stream struct {
    s state
    // ks is a remaining key stream byte, if any.
    //
    // There is a remaining key stream byte, its high bits will
    // be set.
    ks uint16
}

// NewCipher creates a Grain128a stream cipher.
//
// Grain128a must not be used to encrypt more than 2^80 bits per
// key, nonce pair.
func NewStreamCipher(key, nonce []byte) (cipher.Stream, error) {
    if len(key) != KeySize {
        return nil, errors.New("cryptobin/grain: bad key length")
    }

    var s stream
    s.s.setKey(key)
    s.s.init(nonce)

    return &s, nil
}

func (s *stream) XORKeyStream(dst, src []byte) {
    if len(src) == 0 {
        return
    }
    if len(dst) < len(src) {
        panic("cryptobin/grain: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/grain: invalid buffer overlap")
    }

    dst = dst[:len(src)]

    // Remaining key stream.
    const mask = 0xff00
    if s.ks&mask != 0 {
        dst[0] = src[0] ^ byte(s.ks)
        src = src[1:]
        dst = dst[1:]
    }

    for len(src) >= 2 {
        v := binary.LittleEndian.Uint16(src)
        binary.LittleEndian.PutUint16(dst, v^getkb(next(&s.s)))
        src = src[2:]
        dst = dst[2:]
    }

    if len(src) > 0 {
        w := getkb(next(&s.s))
        s.ks = mask | w>>8
        dst[0] = src[0] ^ byte(w)
    } else {
        s.ks = 0
    }
}
