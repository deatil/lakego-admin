package fernet

import (
    "io"
    "errors"
    "crypto/rand"
    "encoding/hex"
    "encoding/base64"
)

var (
    errKeyLen   = errors.New("go-cryptobin/fernet: key decodes to wrong size")
    errNoKeys   = errors.New("go-cryptobin/fernet: no keys provided")
    errKeyShort = errors.New("go-cryptobin/fernet: key too short")
)

// Key represents a key.
type Key struct {
    Value [32]byte
}

func NewKey(k []byte) (*Key, error) {
    if len(k) != 32 {
        return nil, errKeyShort
    }

    key := &Key{}
    copy(key.Value[:], k)

    return key, nil
}

func (k *Key) cryptBytes() []byte {
    return k.Value[len(k.Value)/2:]
}

func (k *Key) signBytes() []byte {
    return k.Value[:len(k.Value)/2]
}

// Generate initializes k with pseudorandom data from package crypto/rand.
func (k *Key) Generate() error {
    _, err := io.ReadFull(rand.Reader, k.Value[:])
    return err
}

// Encode returns the URL-safe base64 encoding of k.
func (k *Key) Encode() string {
    return encoding.EncodeToString(k.Value[:])
}

// Generate initializes k with pseudorandom data from package crypto/rand.
func GenerateKey() *Key {
    k := &Key{}
    k.Generate()

    return k
}

// DecodeKey decodes a key from s and returns it. The key can be in
// hexadecimal, standard base64, or URL-safe base64.
func DecodeKey(s string) (*Key, error) {
    var b []byte
    var err error
    if s == "" {
        return nil, errors.New("go-cryptobin/fernet: empty key")
    }

    if len(s) == hex.EncodedLen(32) {
        b, err = hex.DecodeString(s)
    } else {
        b, err = base64.StdEncoding.DecodeString(s)
        if err != nil {
            b, err = base64.URLEncoding.DecodeString(s)
        }
    }

    if err != nil {
        return nil, err
    }

    if len(b) != 32 {
        return nil, errKeyLen
    }

    k := new(Key)
    copy(k.Value[:], b)
    return k, nil
}

// DecodeKeys decodes each element of k using DecodeKey and returns the
// resulting keys. Requires at least one key.
func DecodeKeys(k ...string) ([]*Key, error) {
    if len(k) == 0 {
        return nil, errNoKeys
    }

    var err error
    ks := make([]*Key, len(k))
    for i, s := range k {
        ks[i], err = DecodeKey(s)
        if err != nil {
            return nil, err
        }
    }

    return ks, nil
}

