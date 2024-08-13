package rabin

import (
    "io"
    "errors"
    "crypto"
    "math/big"
    "crypto/sha256"
    "encoding/asn1"
)

var (
    zero  = new(big.Int).SetInt64(0)
    one   = new(big.Int).SetInt64(1)
    two   = new(big.Int).SetInt64(2)
    three = new(big.Int).SetInt64(3)
    four  = new(big.Int).SetInt64(4)
    five  = new(big.Int).SetInt64(5)
)

type privateKeyInfo struct {
    P, Q *big.Int
}

// PublicKey represents an Rabin public key.
type PublicKey struct {
    N *big.Int
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return pub.N.Cmp(xx.N) == 0
}

// Encrypt data
func (pub *PublicKey) Encrypt(plaintext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    length := uint32(len(plaintext))
    p := new(big.Int).SetBytes(plaintext)

    hashed := sha256.Sum256(plaintext)

    ciphertext := squareAndMultiple(p, two, pub.N)
    ctBytes := ciphertext.Bytes()

    // ct = length + ciphertext + hashed
    ct := make([]byte, 4 + len(ctBytes) + 32)

    putu32(ct[0:], length)
    copy(ct[4:], ctBytes)
    copy(ct[4 + len(ctBytes):], hashed[:])

    return ct, nil
}

// PrivateKey represents an Rabin private key.
type PrivateKey struct {
    PublicKey
    P, Q *big.Int
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*PrivateKey)
    if !ok {
        return false
    }

    return priv.P.Cmp(xx.P) == 0 &&
        priv.Q.Cmp(xx.Q) == 0 &&
        priv.PublicKey.Equal(&xx.PublicKey)
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
    return &priv.PublicKey
}

// crypto.Decrypter
func (priv *PrivateKey) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
    if len(ciphertext) <= 36 {
        return nil, errors.New("cryptobin/rabin: ciphertext data too short.")
    }

    length := int(getu32(ciphertext[:4]))

    h := ciphertext[len(ciphertext) - 32:]
    ct := ciphertext[4:len(ciphertext) - 32]

    c := new(big.Int).SetBytes(ct)

    // decrypt ciphertext
    m1, m2, m3, m4 := decrypt(priv.P, priv.Q, c, priv.N)

    var ok bool
    var b []byte
    if ok, b = hashEqual(m1, h, length); ok {
        return b, nil
    } else if ok, b = hashEqual(m2, h, length); ok {
        return b, nil
    } else if ok, b = hashEqual(m3, h, length); ok {
        return b, nil
    } else if ok, b = hashEqual(m4, h, length); ok {
        return b, nil
    }

    return nil, errors.New("cryptobin/rabin: decrypt data fail.")
}

func Encrypt(pub *PublicKey, plaintext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    if pub == nil {
        return nil, errors.New("cryptobin/rabin: Public Key is error")
    }

    return pub.Encrypt(plaintext, opts)
}

func Decrypt(priv *PrivateKey, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    if priv == nil {
        return nil, errors.New("cryptobin/rabin: Private Key is error")
    }

    return priv.Decrypt(nil, ciphertext, opts)
}

// GenerateKey generates a random Rabin private key of the given bit size.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
    return GenerateKeyWithBitLength(rand, 64)
}

// GenerateKey generates a random Rabin private key of the given bit size.
// bitLength = 64
func GenerateKeyWithBitLength(rand io.Reader, bitLength int) (*PrivateKey, error) {
    p := generateRabinPrimeNumber(rand, bitLength)
    q := generateRabinPrimeNumber(rand, bitLength)

    n := new(big.Int).Mul(p, q)

    priv := new(PrivateKey)
    priv.P = p
    priv.Q = q
    priv.PublicKey.N = n

    return priv, nil
}

// Unmarshal private key
func NewPrivateKey(raw []byte) (*PrivateKey, error) {
    var prikey privateKeyInfo
    _, err := asn1.Unmarshal(raw, &prikey)
    if err != nil {
        return nil, err
    }

    p := prikey.P
    q := prikey.Q

    n := new(big.Int).Mul(p, q)

    priv := new(PrivateKey)
    priv.P = p
    priv.Q = q
    priv.PublicKey.N = n

    return priv, nil
}

// Marshal private key
func ToPrivateKey(priv *PrivateKey) []byte {
    prikey, err := asn1.Marshal(privateKeyInfo{
        P: priv.P,
        Q: priv.Q,
    })
    if err != nil {
        return nil
    }

    return prikey
}

// Unmarshal public key
func NewPublicKey(raw []byte) (*PublicKey, error) {
    n := new(big.Int).SetBytes(raw)

    pub := &PublicKey{
        N: n,
    }

    return pub, nil
}

// Marshal public key
func ToPublicKey(pub *PublicKey) []byte {
    return pub.N.Bytes()
}
