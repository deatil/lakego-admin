package gost_prfplus

import (
    "hash"
    "errors"
    "crypto/hmac"
)

// prf+ function as defined in RFC 7296 (IKEv2)
func Key(h func() hash.Hash, password, salt []byte, keyLen int) (dst []byte, err error) {
    if len(password) == 0 {
        return nil, errors.New("go-cryptobin/gost_prfplus: empty password")
    }
    if len(salt) == 0 {
        return nil, errors.New("go-cryptobin/gost_prfplus: bad salt length")
    }

    mac := hmac.New(h, password)
    size := mac.Size()

    in := make([]byte, size + len(salt) + 1)
    in[len(in)-1] = byte(0x01)

    copy(in[size:], salt)

    var derived []byte

    derived, err = deriveHash(mac, in[size:])
    if err != nil {
        return
    }

    copy(in[:size], derived)

    dst = make([]byte, keyLen)

    copy(dst, in[:size])
    n := len(dst) / size
    if n == 0 {
        return
    }

    if n*size != len(dst) {
        n++
    }
    n--

    out := dst[size:]
    for i := 0; i < n; i++ {
        in[len(in)-1] = byte(i + 2)

        derived, err = deriveHash(mac, in)
        if err != nil {
            return
        }

        copy(in[:size], derived)
        copy(out, in[:size])

        if i+1 != n {
            out = out[size:]
        }
    }

    return
}

func deriveHash(h hash.Hash, salt []byte) ([]byte, error) {
    h.Reset()

    if _, err := h.Write(salt); err != nil {
        return nil, err
    }

    sum := h.Sum(nil)
    return sum, nil
}
