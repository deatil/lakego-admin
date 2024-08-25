package fernet

import (
    "io"
    "time"
    "crypto/aes"
    "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
    "crypto/cipher"
    "encoding/base64"
)

const (
    version      = byte(0x80)
    tsOffset     = 1
    ivOffset     = tsOffset + 8
    payOffset    = ivOffset + aes.BlockSize
    overhead     = 1 + 8 + aes.BlockSize + sha256.Size // ver + ts + iv + hmac
    maxClockSkew = 60 * time.Second
    uint64Bytes  = 8
)

var encoding = base64.URLEncoding

// EncryptWithTime encrypts and signs msg with key k at timestamp encryptAt
// and returns the resulting fernet token. If msg contains text, the text
// should be encoded with UTF-8 to follow fernet convention.
func EncryptWithTime(msg []byte, k *Key, encryptAt time.Time) (tok []byte, err error) {
    iv := make([]byte, aes.BlockSize)
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    b := make([]byte, encodedLen(len(msg)))
    n := encrypt(b, msg, iv, encryptAt, k)
    tok = make([]byte, encoding.EncodedLen(n))

    encoding.Encode(tok, b[:n])
    return tok, nil
}

// Encrypt encrypts and signs msg with key k and returns the resulting
// fernet token. If msg contains text, the text should be encoded
// with UTF-8 to follow fernet convention.
func Encrypt(msg []byte, k *Key) (tok []byte, err error) {
    return EncryptWithTime(msg, k, time.Now())
}

// DecryptWithTime verifies that tok is a valid fernet token that was signed
// with a key in k at most ttl time ago only if ttl is greater than zero.
// Returns the message contained in tok if tok is valid, otherwise nil.
func DecryptWithTime(tok []byte, ttl time.Duration, k []*Key, now time.Time) (msg []byte) {
    b := make([]byte, encoding.DecodedLen(len(tok)))
    n, _ := encoding.Decode(b, tok)
    for _, k1 := range k {
        msg = decrypt(nil, b[:n], ttl, now, k1)
        if msg != nil {
            return msg
        }
    }

    return nil
}

// Decrypt verifies that tok is a valid fernet token that was signed
// with a key in k at most ttl time ago only if ttl is greater than zero.
// Returns the message contained in tok if tok is valid, otherwise nil.
func Decrypt(tok []byte, ttl time.Duration, k []*Key) (msg []byte) {
    return DecryptWithTime(tok, ttl, k, time.Now())
}

// encrypt msg
func encrypt(tok, msg, iv []byte, ts time.Time, k *Key) int {
    tok[0] = version
    putu64(tok[tsOffset:], uint64(ts.Unix()))
    copy(tok[ivOffset:], iv)

    p := tok[payOffset:]
    n := pad(p, msg, aes.BlockSize)

    block, _ := aes.NewCipher(k.cryptBytes())
    cipher.NewCBCEncrypter(block, iv).CryptBlocks(p[:n], p[:n])

    hashed := hmacHash(tok[:payOffset+n], k.signBytes())
    copy(p[n:], hashed)

    return payOffset + n + sha256.Size
}

// if msg is nil, decrypts in place and returns a slice of tok.
func decrypt(msg, tok []byte, ttl time.Duration, now time.Time, k *Key) []byte {
    if len(tok) < 1+uint64Bytes || tok[0] != version {
        return nil
    }

    ts := time.Unix(int64(getu64(tok[1:])), 0)
    if ttl > 0 && (now.After(ts.Add(ttl)) || ts.After(now.Add(maxClockSkew))) {
        return nil
    }

    n := len(tok) - sha256.Size
    if n <= 0 {
        return nil
    }

    hashed := hmacHash(tok[:n], k.signBytes())
    if subtle.ConstantTimeCompare(tok[n:], hashed) != 1 {
        return nil
    }

    pay := tok[payOffset:n]
    if len(pay)%aes.BlockSize != 0 {
        return nil
    }

    if msg != nil {
        copy(msg, pay)
        pay = msg
    }

    iv := tok[ivOffset:ivOffset+aes.BlockSize]

    block, err := aes.NewCipher(k.cryptBytes())
    if err != nil {
        return nil
    }
    cipher.NewCBCDecrypter(block, iv).CryptBlocks(pay, pay)

    return unpad(pay)
}
