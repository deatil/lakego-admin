package elgamal

import (
    "io"
    "time"
    "errors"
    "math/big"
    "crypto"
    "crypto/rand"
    "crypto/subtle"
    "encoding/asn1"
    math_rand "math/rand"
)

/*
from docs:
1. https://en.wikipedia.org/wiki/ElGamal_encryption
2. https://en.wikipedia.org/wiki/ElGamal_signature_scheme
3. https://dl.acm.org/doi/pdf/10.1145/3214303
4. https://pkg.go.dev/golang.org/x/crypto/openpgp/elgamal
*/

var zero = big.NewInt(0)
var one = big.NewInt(1)
var two = big.NewInt(2)

var ErrMessageLarge = errors.New("go-cryptobin/elgamal: message is larger than public key size")
var ErrCipherLarge  = errors.New("go-cryptobin/elgamal: cipher is larger than public key size")

// PublicKey represents a Elgamal public key.
type PublicKey struct {
    G, P, Y *big.Int
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return bigIntEqual(pub.G, xx.G) &&
        bigIntEqual(pub.P, xx.P) &&
        bigIntEqual(pub.Y, xx.Y)
}

// Verify verifies signature over the given hash and signature values (r & s).
// It returns true as a boolean value if signature is verify correctly. Otherwise
// it returns false along with error message.
func (pub *PublicKey) Verify(hash, sig []byte) (bool, error) {
    return VerifyASN1(pub, hash, sig)
}

// Encrypt encrypts a plain text represented as a byte array.
func (pub *PublicKey) Encrypt(random io.Reader, message []byte) ([]byte, error) {
    return EncryptASN1(random, pub, message)
}

// PrivateKey represents Elgamal private key.
type PrivateKey struct {
    PublicKey

    X *big.Int
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*PrivateKey)
    if !ok {
        return false
    }

    return priv.PublicKey.Equal(&xx.PublicKey) &&
        bigIntEqual(priv.X, xx.X)
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
    return &priv.PublicKey
}

// Signature generates signature over the given hash. It returns signature
// value consisting of two parts "r" and "s" as byte arrays.
func (priv *PrivateKey) Sign(random io.Reader, hash []byte, opts crypto.SignerOpts) (signature []byte, err error) {
    return SignASN1(random, priv, hash)
}

// Decrypt decrypts the passed cipher text. It returns an
// error if cipher text value is larger than modulus P of Public key.
func (priv *PrivateKey) Decrypt(random io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
    return DecryptASN1(priv, msg)
}

// GenerateKey generates elgamal private key according
// to given bit size and probability. Moreover, the given probability
// value is used in choosing prime number P for performing n Miller-Rabin
// tests with 1 - 1/(4^n) probability false rate.
func GenerateKey(random io.Reader, bitsize, probability int) (*PrivateKey, error) {
    // p is prime number
    // q is prime group order
    // g is cyclic group generator Zp
    p, q, g, err := GeneratePQZp(random, bitsize, probability)
    if err != nil {
        return nil, err
    }

    randSource := math_rand.New(math_rand.NewSource(time.Now().UnixNano()))
    // choose random integer x from {1...(q-1)}
    priv := new(big.Int).Rand(randSource, new(big.Int).Sub(q, one))
    // y = g^p mod p
    y := new(big.Int).Exp(g, priv, p)

    return &PrivateKey{
        PublicKey: PublicKey{
            G: g, // cyclic group generator Zp
            P: p, // prime number
            Y: y, // y = g^p mod p
        },
        X: priv, // secret key x
    }, nil
}

// Encrypt
func Encrypt(random io.Reader, pub *PublicKey, msg []byte) (c1, c2 *big.Int, err error) {
    pLen := (pub.P.BitLen() + 7) / 8
    if len(msg) > pLen-11 {
        err = errors.New("go-cryptobin/elgamal: message too long")
        return
    }

    // EM = 0x02 || PS || 0x00 || M
    em := make([]byte, pLen-1)
    em[0] = 2
    ps, mm := em[1:len(em)-len(msg)-1], em[len(em)-len(msg):]
    err = nonZeroRandomBytes(ps, random)
    if err != nil {
        return
    }
    em[len(em)-len(msg)-1] = 0
    copy(mm, msg)

    return EncryptLegacy(random, pub, em)
}

// Decrypt
func Decrypt(priv *PrivateKey, c1, c2 *big.Int) (msg []byte, err error) {
    em, err := DecryptLegacy(priv, c1, c2)
    if err != nil {
        return nil, err
    }

    firstByteIsTwo := subtle.ConstantTimeByteEq(em[0], 2)

    var lookingForIndex, index int
    lookingForIndex = 1

    for i := 1; i < len(em); i++ {
        equals0 := subtle.ConstantTimeByteEq(em[i], 0)
        index = subtle.ConstantTimeSelect(lookingForIndex&equals0, i, index)
        lookingForIndex = subtle.ConstantTimeSelect(equals0, 0, lookingForIndex)
    }

    if firstByteIsTwo != 1 || lookingForIndex != 0 || index < 9 {
        return nil, errors.New("go-cryptobin/elgamal: decryption error")
    }

    return em[index+1:], nil
}

// EncryptLegacy
func EncryptLegacy(random io.Reader, pub *PublicKey, msg []byte) (c1, c2 *big.Int, err error) {
    m := new(big.Int).SetBytes(msg)

    k, err := rand.Int(random, pub.P)
    if err != nil {
        return
    }

    c1 = new(big.Int).Exp(pub.G, k, pub.P)
    s := new(big.Int).Exp(pub.Y, k, pub.P)
    c2 = s.Mul(s, m)
    c2.Mod(c2, pub.P)

    return
}

// DecryptLegacy
func DecryptLegacy(priv *PrivateKey, c1, c2 *big.Int) (msg []byte, err error) {
    s := new(big.Int).Exp(c1, priv.X, priv.P)
    if s.ModInverse(s, priv.P) == nil {
        return nil, errors.New("go-cryptobin/elgamal: invalid private key")
    }

    s.Mul(s, c2)
    s.Mod(s, priv.P)
    em := s.Bytes()

    return em, nil
}

// c1 and c2 data
type elgamalEncrypt struct {
    C1, C2 *big.Int
}

// Encrypt Asn1
func EncryptASN1(random io.Reader, pub *PublicKey, message []byte) ([]byte, error) {
    c1, c2, err := Encrypt(random, pub, message)
    if err != nil {
        return nil, err
    }

    return asn1.Marshal(elgamalEncrypt{
        C1: c1,
        C2: c2,
    })
}

// Decrypt Asn1
func DecryptASN1(priv *PrivateKey, cipherData []byte) ([]byte, error) {
    var enc elgamalEncrypt
    _, err := asn1.Unmarshal(cipherData, &enc)
    if err != nil {
        return nil, err
    }

    return Decrypt(priv, enc.C1, enc.C2)
}

// Encrypt bytes
func EncryptBytes(random io.Reader, pub *PublicKey, message []byte) ([]byte, error) {
    c1, c2, err := Encrypt(random, pub, message)
    if err != nil {
        return nil, err
    }

    byteLen := pub.P.BitLen()

    buf := make([]byte, 2*byteLen)

    c1.FillBytes(buf[      0:  byteLen])
    c2.FillBytes(buf[byteLen:2*byteLen])

    return buf, nil
}

// Decrypt bytes
func DecryptBytes(priv *PrivateKey, cipherData []byte) ([]byte, error) {
    byteLen := priv.P.BitLen()
    if len(cipherData) != 2*byteLen {
        return nil, errors.New("go-cryptobin/elgamal: Invalid message")
    }

    c1 := new(big.Int).SetBytes(cipherData[      0:  byteLen])
    c2 := new(big.Int).SetBytes(cipherData[byteLen:2*byteLen])

    if c1.Cmp(priv.P) >= 0 || c2.Cmp(priv.P) >= 0 {
        return nil, errors.New("go-cryptobin/elgamal: Invalid message")
    }

    return Decrypt(priv, c1, c2)
}

// HomomorphicEncTwo performs homomorphic operation over two passed chiphers.
// Elgamal has multiplicative homomorphic property, so resultant cipher
// contains the product of two numbers.
func HomomorphicEncTwo(pub *PublicKey, c1, c2, c1dash, c2dash []byte) (*big.Int, *big.Int, error) {
    cipher1 := new(big.Int).SetBytes(c1)
    cipher2 := new(big.Int).SetBytes(c2)
    if cipher1.Cmp(pub.P) == 1 && cipher2.Cmp(pub.P) == 1 { //  (c1, c2) < P
        return nil, nil, ErrCipherLarge
    }

    // In the context of elgamal encryption, (cipher1,cipher2) and
    // (cipher1dash, cipher2dash) both are valid ciphers and represented
    // by different variable names.
    cipher1dash := new(big.Int).SetBytes(c1dash)
    cipher2dash := new(big.Int).SetBytes(c2dash)
    if cipher1dash.Cmp(pub.P) == 1 && cipher2dash.Cmp(pub.P) == 1 { //  (c1dash, c2dash) < P
        return nil, nil, ErrCipherLarge
    }

    // C1 = c1 * c1dash mod p
    C1 := new(big.Int).Mod(
        new(big.Int).Mul(cipher1, cipher1dash),
        pub.P,
    )

    // C2 = c2 * c2dash mod p
    C2 := new(big.Int).Mod(
        new(big.Int).Mul(cipher2, cipher2dash),
        pub.P,
    )

    return C1, C2, nil
}

// HommorphicEncMultiple performs homomorphic operation over multiple passed chiphers.
// Elgamal has multiplicative homomorphic property, so resultant cipher
// contains the product of multiple numbers.
func HommorphicEncMultiple(pub *PublicKey, ciphertext [][2][]byte) (*big.Int, *big.Int, error) {
    // C1, C2, _ := pub.Encrypt(one.Bytes())
    C1 := one // since, c = 1^e mod n is equal to 1
    C2 := one

    for i := 0; i < len(ciphertext); i++ {
        c1 := new(big.Int).SetBytes(ciphertext[i][0])
        c2 := new(big.Int).SetBytes(ciphertext[i][1])

        // (c1, c2) < P
        if c1.Cmp(pub.P) == 1 && c2.Cmp(pub.P) == 1 {
            return nil, nil, ErrCipherLarge
        }

        // C1 = (c1)_1 * (c1)_2 * (c1)_3 ...(c1)_n mod p
        C1 = new(big.Int).Mod(
            new(big.Int).Mul(
                C1,
                c1,
            ),
            pub.P,
        )

        // C2 = (c2)_1 * (c2)_2 * (c2)_3 ...(c2)_n mod p
        C2 = new(big.Int).Mod(
            new(big.Int).Mul(
                C2,
                c2,
            ),
            pub.P,
        )
    }

    return C1, C2, nil
}

// Sign hash
func Sign(random io.Reader, priv *PrivateKey, hash []byte) (*big.Int, *big.Int, error) {
    k := new(big.Int)
    gcd := new(big.Int)

    var err error

    // choosing random integer k from {1...(p-2)}, such that
    // gcd(k,(p-1)) should be equal to 1.
    for {
        k, err = rand.Int(random, new(big.Int).Sub(priv.P, two))
        if err != nil {
            return nil, nil, err
        }

        if k.Cmp(one) == 0 {
            continue
        }

        gcd = gcd.GCD(nil, nil, k, new(big.Int).Sub(priv.P, one))
        if gcd.Cmp(one) == 0 {
            break
        }
    }

    // m as H(m)
    m := new(big.Int).SetBytes(hash)

    // r = g^k mod p
    r := new(big.Int).Exp(priv.G, k, priv.P)
    // xr = x * r
    xr := new(big.Int).Mod(
        new(big.Int).Mul(r, priv.X),
        new(big.Int).Sub(priv.P, one),
    )

    // hmxr = [H(m)-xr]
    hmxr := new(big.Int).Sub(m, xr)
    // k = k^(-1)
    k = k.ModInverse(k, new(big.Int).Sub(priv.P, one))

    // s = [H(m) -xr]k^(-1) mod (p-1)
    s := new(big.Int).Mod(
        new(big.Int).Mul(hmxr, k),
        new(big.Int).Sub(priv.P, one),
    )

    return r, s, nil
}

// Verify hash
func Verify(pub *PublicKey, hash []byte, r, s *big.Int) (bool, error) {
    // verify that 0 < r < p
    signr := new(big.Int).Set(r)
    if signr.Cmp(zero) == -1 {
        return false, errors.New("go-cryptobin/elgamal: r is smaller than zero")
    } else if signr.Cmp(pub.P) == +1 {
        return false, errors.New("go-cryptobin/elgamal: r is larger than public key p")
    }

    signs := new(big.Int).Set(s)
    if signs.Cmp(zero) == -1 {
        return false, errors.New("go-cryptobin/elgamal: s is smaller than zero")
    } else if signs.Cmp(new(big.Int).Sub(pub.P, one)) == +1 {
        return false, errors.New("go-cryptobin/elgamal: s is larger than public key p")
    }

    // m as H(m)
    m := new(big.Int).SetBytes(hash)

    // ghashm = g^[H(m)] mod p
    ghashm := new(big.Int).Exp(pub.G, m, pub.P)

    // y^r * r*s mod p
    YrRs := new(big.Int).Mod(
        new(big.Int).Mul(
            new(big.Int).Exp(pub.Y, signr, pub.P),
            new(big.Int).Exp(signr, signs, pub.P),
        ),
        pub.P,
    )

    // g^H(m) y^r * r*s mod p
    if ghashm.Cmp(YrRs) == 0 {
        return true, nil // signature is verified
    }

    return false, errors.New("go-cryptobin/elgamal: signature is not verified")
}

// r and s data
type elgamalSignature struct {
    R, S *big.Int
}

// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the ASN.1 encoded signature.
func SignASN1(rand io.Reader, priv *PrivateKey, hash []byte) ([]byte, error) {
    r, s, err := Sign(rand, priv, hash)
    if err != nil {
        return nil, err
    }

    return asn1.Marshal(elgamalSignature{
        R: r,
        S: s,
    })
}

// VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func VerifyASN1(pub *PublicKey, hash, sig []byte) (bool, error) {
    var sign elgamalSignature
    _, err := asn1.Unmarshal(sig, &sign)
    if err != nil {
        return false, err
    }

    return Verify(pub, hash, sign.R, sign.S)
}

// 签名返回明文拼接数据
// sign data and return Bytes marshal data
func SignBytes(rand io.Reader, priv *PrivateKey, hash []byte) ([]byte, error) {
    r, s, err := Sign(rand, priv, hash)
    if err != nil {
        return nil, err
    }

    byteLen := priv.P.BitLen()

    buf := make([]byte, 2*byteLen)

    r.FillBytes(buf[      0:  byteLen])
    s.FillBytes(buf[byteLen:2*byteLen])

    return buf, nil
}

// 验证明文拼接的数据 bytes(r + s)
// Verify Bytes marshal data
func VerifyBytes(pub *PublicKey, hash, sign []byte) (bool, error) {
    byteLen := pub.P.BitLen()
    if len(sign) != 2*byteLen {
        return false, errors.New("go-cryptobin/elgamal: signature is not verified")
    }

    r := new(big.Int).SetBytes(sign[      0:  byteLen])
    s := new(big.Int).SetBytes(sign[byteLen:2*byteLen])

    return Verify(pub, hash, r, s)
}

// Gen emit <p,q,g>.
// p = 2q + 1, p,q - safe primes
// g - cyclic group generator Zp
// performs n Miller-Rabin tests with 1 - 1/(4^n) probability false rate.
// Gain n - bit width for integer & probability rang for MR.
// It returns p, q, g and write error message.
func GeneratePQZp(random io.Reader, n, probability int) (*big.Int, *big.Int, *big.Int, error) {
    for {
        q, err := rand.Prime(random, n-1)
        if err != nil {
            return nil, nil, nil, err
        }

        t := new(big.Int).Mul(q, two)
        p := new(big.Int).Add(t, one)
        if p.ProbablyPrime(probability) {
            for {
                g, err := rand.Int(random, p)
                if err != nil {
                    return nil, nil, nil, err
                }

                b := new(big.Int).Exp(g, two, p)
                if b.Cmp(one) == 0 {
                    continue
                }

                b = new(big.Int).Exp(g, q, p)
                if b.Cmp(one) == 0 {
                    return p, q, g, nil
                }
            }
        }
    }

    return nil, nil, nil, errors.New("go-cryptobin/elgamal: generate key fail")
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

// nonZeroRandomBytes fills the given slice with non-zero random octets.
func nonZeroRandomBytes(s []byte, rand io.Reader) (err error) {
    _, err = io.ReadFull(rand, s)
    if err != nil {
        return
    }

    for i := 0; i < len(s); i++ {
        for s[i] == 0 {
            _, err = io.ReadFull(rand, s[i:i+1])
            if err != nil {
                return
            }
        }
    }

    return
}
