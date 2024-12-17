package bcrypt_pbkdf

import (
    "errors"
    "crypto/sha512"
    "crypto/subtle"
    "encoding/binary"

    "golang.org/x/crypto/blowfish"
)

// bcrypt pbkdf
func Key(password, salt []byte, rounds, keyLen int) ([]byte, error) {
    if rounds < 1 {
        return nil, errors.New("go-cryptobin/bcrypt_pbkdf: number of rounds is too small")
    }
    if len(password) == 0 {
        return nil, errors.New("go-cryptobin/bcrypt_pbkdf: empty password")
    }
    if len(salt) == 0 || len(salt) > 1<<20 {
        return nil, errors.New("go-cryptobin/bcrypt_pbkdf: bad salt length")
    }

    if keyLen > 1024 {
        return nil, errors.New("go-cryptobin/bcrypt_pbkdf: keyLen is too large")
    }

    var shapass, shasalt [sha512.Size]byte
    var out, tmp [32]byte
    var cnt [4]byte

    numBlocks := (keyLen + len(out) - 1) / len(out)
    key := make([]byte, numBlocks*len(out))

    h := sha512.New()
    h.Write(password)
    h.Sum(shapass[:0])

    for block := 1; block <= numBlocks; block++ {
        h.Reset()
        h.Write(salt)

        binary.BigEndian.PutUint32(cnt[:], uint32(block))
        h.Write(cnt[:])

        bcryptHash(tmp[:], shapass[:], h.Sum(shasalt[:0]))
        copy(out[:], tmp[:])

        for i := 2; i <= rounds; i++ {
            h.Reset()
            h.Write(tmp[:])
            bcryptHash(tmp[:], shapass[:], h.Sum(shasalt[:0]))

            subtle.XORBytes(out[:], out[:], tmp[:])
        }

        for i, v := range out {
            key[i*numBlocks+(block-1)] = v
        }
    }

    return key[:keyLen], nil
}

var magic = []byte("OxychromaticBlowfishSwatDynamite")

func bcryptHash(out, shapass, shasalt []byte) {
    c, err := blowfish.NewSaltedCipher(shapass, shasalt)
    if err != nil {
        panic(err)
    }

    for i := 0; i < 64; i++ {
        blowfish.ExpandKey(shasalt, c)
        blowfish.ExpandKey(shapass, c)
    }

    copy(out, magic)
    for i := 0; i < 32; i += 8 {
        for j := 0; j < 64; j++ {
            c.Encrypt(out[i:i+8], out[i:i+8])
        }
    }

    for i := 0; i < 32; i += 4 {
        out[i+3], out[i+2], out[i+1], out[i] = out[i], out[i+1], out[i+2], out[i+3]
    }
}
