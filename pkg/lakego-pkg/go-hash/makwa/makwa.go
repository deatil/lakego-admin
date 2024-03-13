// Package makwa implements the Makwa password hashing algorithm.
//
// Makwa is a candidate in the Password Hashing Competition which uses squaring
// modulo Blum integers to provide a one-way function with number-theoretic
// security.
//
// https://password-hashing.net/submissions/specs/Makwa-v0.pdf
package makwa

import (
    "bytes"
    "crypto/hmac"
    "crypto/rand"
    "crypto/subtle"
    "errors"
    "hash"
    "math/big"
)

// ErrBadPassword is returned when a bad password is provided.
var ErrBadPassword = errors.New("bad password")

// ErrWrongParams is returned when a password is being checked using the wrong
// parameters.
var ErrWrongParams = errors.New("wrong parameters")

// ErrInvalidWorkFactor is returned when the given work factor cannot be encoded
// as a power of 2 or 3.
var ErrInvalidWorkFactor = errors.New("invalid work factor")

// CheckPassword safely compares a password to a digest of a password.
func CheckPassword(params PublicParameters, digest *Digest, password []byte) error {
    if !bytes.Equal(digest.ModulusID, params.ModulusID()) {
        return ErrWrongParams
    }

    d, err := Hash(
        params,
        password,
        digest.Salt,
        digest.WorkFactor,
        digest.PreHash,
        digest.PostHashLen,
    )
    if err != nil {
        return err
    }

    if subtle.ConstantTimeCompare(digest.Hash, d.Hash) != 1 {
        return ErrBadPassword
    }
    return nil
}

// Extend re-hashes the given digest to increase its work factor.
func Extend(params PublicParameters, digest *Digest, workFactor int) error {
    if !bytes.Equal(digest.ModulusID, params.ModulusID()) {
        return ErrWrongParams
    }

    if digest.PostHashLen > 0 {
        return errors.New("digest cannot be extended")
    }

    x := new(big.Int).SetBytes(digest.Hash)
    for i := digest.WorkFactor; i < workFactor; i++ {
        x = new(big.Int).Exp(x, two, params.N)
    }
    digest.Hash = x.Bytes()
    digest.WorkFactor = workFactor

    return nil
}

// Recover uses the private parameters to recover the plaintext of a password
// digest.
func Recover(params PrivateParameters, digest *Digest) ([]byte, error) {
    if digest.PreHash || digest.PostHashLen > 0 {
        return nil, errors.New("password cannot be recovered")
    }

    if !bytes.Equal(digest.ModulusID, params.ModulusID()) {
        return nil, ErrWrongParams
    }

    y := new(big.Int).SetBytes(digest.Hash)
    p := params.P
    q := params.Q
    iq := new(big.Int).ModInverse(q, p)
    ep := sqrtExp(p, digest.WorkFactor+1)
    eq := sqrtExp(q, digest.WorkFactor+1)

    x1p := new(big.Int).Mod(y, p)
    x1p = x1p.Exp(x1p, ep, p)

    x1q := new(big.Int).Mod(y, q)
    x1q = x1q.Exp(x1q, eq, q)

    x2p := new(big.Int).Sub(p, x1p)
    x2p = x2p.Mod(x2p, p)

    x2q := new(big.Int).Sub(q, x1q)
    x2q = x2q.Mod(x2q, q)

    xc := []*big.Int{
        crt(p, q, iq, x1p, x1q),
        crt(p, q, iq, x1p, x2q),
        crt(p, q, iq, x2p, x1q),
        crt(p, q, iq, x2p, x2q),
    }

    for _, v := range xc {
        buf := pad(params.N, v)

        if buf[0] != 0x00 {
            continue
        }

        k := len(buf)
        u := int(buf[k-1]) & 0xFF
        if u > (k - 32) {
            continue
        }

        password := buf[k-u-1 : len(buf)-1]

        x := kdf(params.Hash, append(append(digest.Salt, password...), byte(u)), k-2-u)
        x = append(append(append([]byte{0x00}, x...), password...), byte(u))

        if subtle.ConstantTimeCompare(x, buf) == 1 {
            return password, nil
        }
    }

    return nil, errors.New("password cannot be recovered")
}

// Hash returns a digest of the given password using the given parameters. If
// the given salt is nil, generates a random salt of sufficient length.
func Hash(params PublicParameters, password, salt []byte, workFactor int, preHash bool, postHashLen int) (*Digest, error) {
    if _, _, err := wfMant(uint32(workFactor)); err != nil {
        return nil, err
    }

    if salt == nil {
        salt = make([]byte, 16)
        if _, err := rand.Read(salt); err != nil {
            return nil, err
        }
    }

    if preHash {
        password = kdf(params.Hash, password, 64)
    }

    k := params.N.BitLen() / 8
    if k < 160 {
        return nil, errors.New("modulus too short")
    }

    u := len(password)
    if u > 255 || u > (k-32) {
        return nil, errors.New("password too long")
    }

    // sb = KDF(salt || password || BYTE(u), k - 2 - u)
    sb := kdf(params.Hash, append(append(salt, password...), byte(u)), k-2-u)

    //xb = BYTE(0x00) || sb || password || BYTE(u)
    xb := append(append(append([]byte{0x00}, sb...), password...), byte(u))

    x := new(big.Int).SetBytes(xb)
    for i := 0; i <= workFactor; i++ {
        x = new(big.Int).Exp(x, two, params.N)
    }

    out := pad(params.N, x)
    if postHashLen > 0 {
        out = kdf(params.Hash, out, postHashLen)
    }

    return &Digest{
        ModulusID:   params.ModulusID(),
        Hash:        out,
        Salt:        salt,
        WorkFactor:  workFactor,
        PreHash:     preHash,
        PostHashLen: postHashLen,
    }, nil
}

var (
    one = big.NewInt(1)
    two = big.NewInt(2)
)

func pad(modulus, x *big.Int) []byte {
    modLen := (modulus.BitLen() + 7) >> 3
    out := x.Bytes()
    if len(out) < modLen {
        out = append(make([]byte, modLen-len(out)), out...)
    }
    return out[:modLen]
}

func kdf(alg func() hash.Hash, data []byte, outLen int) []byte {
    // r = output length of h() in bytes
    r := alg().Size()

    // V = BYTE(0x01) || BYTE(0x01) || ... || BYTE(0x01)  # such that len(V) = r
    v := make([]byte, r)
    for i := range v {
        v[i] = 0x01
    }

    // K = BYTE(0x00) || BYTE(0x00) || ... || BYTE(0x00)  # such that len(K) = r
    k := make([]byte, r)

    // K = HMAC(h, K, V || BYTE(0x00) || data)
    k = mac(alg, k, append(append(v, 0x00), data...))

    // V = HMAC(h, K, V)
    v = mac(alg, k, v)

    // K = HMAC(h, K, V || BYTE(0x01) || data)
    k = mac(alg, k, append(append(v, 0x01), data...))

    // V = HMAC(h, K, V)
    v = mac(alg, k, v)

    // T = empty
    var t []byte

    // while len(T) < out_len
    for len(t) < int(outLen) {
        // V = HMAC(h, K, V)
        v = mac(alg, k, v)

        //  T = T || V
        t = append(t, v...)
    }

    // return trunc(T, out_len)
    return t[:outLen]
}

func mac(alg func() hash.Hash, k, v []byte) []byte {
    h := hmac.New(alg, k)
    _, _ = h.Write(v)
    return h.Sum(nil)
}

func wfMant(wf uint32) (mant, log uint32, err error) {
    j := uint32(0)
    for wf > 3 && (wf&1) == 0 {
        wf = (wf >> 1) | (wf << 31)
        j++
    }

    if !(wf == 2 || wf == 3) {
        err = ErrInvalidWorkFactor
        return
    }

    return wf, j, nil
}

func sqrtExp(p *big.Int, w int) *big.Int {
    e := new(big.Int).Add(p, one)
    e = e.Rsh(e, 2)

    p2 := new(big.Int).Sub(p, one)
    return new(big.Int).Exp(e, big.NewInt(int64(w)), p2)
}

func crt(p, q, iq, zp, zq *big.Int) *big.Int {
    h := new(big.Int).Sub(zp, zq)
    h = h.Mul(h, iq)
    h = h.Mod(h, p)

    z := new(big.Int).Mul(q, h)
    return z.Add(zq, z)
}
