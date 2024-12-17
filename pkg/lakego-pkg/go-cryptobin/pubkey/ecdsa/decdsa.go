package ecdsa

import (
    "io"
    "hash"
    "bytes"
    "errors"
    "math/big"
    "crypto/hmac"
    "crypto/ecdsa"
    "crypto/elliptic"
    "encoding/asn1"
)

type Hasher = func() hash.Hash

type dSignature struct {
    R, S *big.Int
}

func DSignASN1(priv *ecdsa.PrivateKey, csprng io.Reader, data []byte, hashFunc Hasher) ([]byte, error) {
    r, s, err := DSign(priv, csprng, data, hashFunc)
    if err != nil {
        return nil, err
    }

    return asn1.Marshal(dSignature{r, s})
}

func DSignBytes(priv *ecdsa.PrivateKey, csprng io.Reader, data []byte, hashFunc Hasher) ([]byte, error) {
    r, s, err := DSign(priv, csprng, data, hashFunc)
    if err != nil {
        return nil, err
    }

    curve := priv.Curve

    byteLen := (curve.Params().BitSize + 7) / 8

    buf := make([]byte, 2*byteLen)

    r.FillBytes(buf[      0:  byteLen])
    s.FillBytes(buf[byteLen:2*byteLen])

    return buf, nil
}

var errZeroParam = errors.New("zero parameter")

func DSign(priv *ecdsa.PrivateKey, csprng io.Reader, hash []byte, hashFunc Hasher) (r, s *big.Int, err error) {
    c := priv.Curve

    // SEC 1, Version 2.0, Section 4.1.3
    N := c.Params().N
    if N.Sign() == 0 {
        return nil, nil, errZeroParam
    }

    var k, kInv *big.Int
    for {
        for {
            if csprng != nil {
                k, err = randFieldElement(c, csprng)
                if err != nil {
                    return nil, nil, err
                }
            } else {
                k = new(big.Int)
                qlen := c.Params().BitSize

                rfc6979Nonce(k, N, qlen, priv.D, hash, hashFunc)
            }

            kInv = new(big.Int).ModInverse(k, N)

            r, _ = c.ScalarBaseMult(k.Bytes())
            r.Mod(r, N)
            if r.Sign() != 0 {
                break
            }
        }

        e := hashToInt(hash, c)
        s = new(big.Int).Mul(priv.D, r)
        s.Add(s, e)
        s.Mul(s, kInv)
        s.Mod(s, N) // N != 0
        if s.Sign() != 0 {
            break
        }
    }

    return r, s, nil
}

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
    orderBits := c.Params().N.BitLen()
    orderBytes := (orderBits + 7) / 8
    if len(hash) > orderBytes {
        hash = hash[:orderBytes]
    }

    ret := new(big.Int).SetBytes(hash)
    excess := len(hash)*8 - orderBits
    if excess > 0 {
        ret.Rsh(ret, uint(excess))
    }
    return ret
}

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.2.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
    // See randomPoint for notes on the algorithm. This has to match, or s390x
    // signatures will come out different from other architectures, which will
    // break TLS recorded tests.
    for {
        N := c.Params().N
        b := make([]byte, (N.BitLen()+7)/8)
        if _, err = io.ReadFull(rand, b); err != nil {
            return
        }
        if excess := len(b)*8 - N.BitLen(); excess > 0 {
            b[0] >>= excess
        }
        k = new(big.Int).SetBytes(b)
        if k.Sign() != 0 && k.Cmp(N) < 0 {
            return
        }
    }
}

/*
 * Deterministic nonce generation function for deterministic ECDSA, as
 * described in RFC6979.
 * NOTE: Deterministic nonce generation for ECDSA is useful against attackers
 * in contexts where only poor RNG/entropy are available, or when nonce bits
 * leaking can be possible through side-channel attacks.
 * However, in contexts where fault attacks are easy to mount, deterministic
 * ECDSA can bring more security risks than regular ECDSA.
 *
 */
func rfc6979Nonce(
    k, q *big.Int,
    qBitLen int,
    x *big.Int,
    hash []byte,
    hashFunc Hasher,
) {
    hsize := hashFunc().Size()
    q_len := (qBitLen + 7) / 8

    /* Steps b. and c.: set V = 0x01 ... 0x01 and K = 0x00 ... 0x00 */
    V := bytes.Repeat([]byte{0x01}, hsize)
    K := make([]byte, hsize)

    priv_key_buff := make([]byte, q_len)
    x.FillBytes(priv_key_buff)

    newHmac := hmac.New(hashFunc, K)
    newHmac.Write(V)

    tmp := []byte{0x00}
    newHmac.Write(tmp)
    newHmac.Write(priv_key_buff)

    /* We compute bits2octets(hash) here */
    k.SetBytes(hash)

    if (8 * hsize) > qBitLen {
        k.Rsh(k, uint((8 * hsize) - qBitLen))
    }
    k.Mod(k, q)

    T := make([]byte, q_len)
    k.FillBytes(T)
    newHmac.Write(T)

    K = newHmac.Sum(nil)

    /* Step e.: set V = HMAC_K(V) */
    V = hmacHash(K, hashFunc, V)

    /*  Step f.: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1)) */
    newHmac = hmac.New(hashFunc, K)
    newHmac.Write(V)

    tmp = []byte{0x01}
    newHmac.Write(tmp)
    newHmac.Write(priv_key_buff)

    /* We compute bits2octets(hash) here */
    newHmac.Write(T)

    K = newHmac.Sum(nil)

    /* Step g.: set V = HMAC_K(V)*/
    V = hmacHash(K, hashFunc, V)

    /* Step h. now apply the generation algorithm until we get
     * a proper nonce value:
     * 1.  Set T to the empty sequence.  The length of T (in bits) is
     * denoted tlen; thus, at that point, tlen = 0.
     * 2.  While tlen < qlen, do the following:
     *    V = HMAC_K(V)
     *    T = T || V
     * 3.  Compute:
     *    k = bits2int(T)
     * If that value of k is within the [1,q-1] range, and is
     * suitable for DSA or ECDSA (i.e., it results in an r value
     * that is not 0; see Section 3.4), then the generation of k is
     * finished.  The obtained value of k is used in DSA or ECDSA.
     * Otherwise, compute:
     *    K = HMAC_K(V || 0x00)
     *    V = HMAC_K(V)
     * and loop (try to generate a new T, and so on).
     */

Restart:
    t_bit_len := 0
    for t_bit_len < qBitLen {
        V = hmacHash(K, hashFunc, V)
        copy(T[byteceil(t_bit_len):], V)
        t_bit_len = t_bit_len + (8 * len(V))
    }

    k.SetBytes(T)

    if (8 * q_len) > qBitLen {
        k.Rsh(k, uint((8 * q_len) - qBitLen))
    }
    k.Mod(k, q)

    if k.Cmp(q) >= 0 {
        /* K = HMAC_K(V || 0x00) */
        newHmac = hmac.New(hashFunc, K)
        newHmac.Write(V)

        tmp := []byte{0x00}
        newHmac.Write(tmp)

        K = newHmac.Sum(nil)

        /* V = HMAC_K(V) */
        V = hmacHash(K, hashFunc, V)

        goto Restart
    }
}

func hmacHash(hmackey []byte, hashFunc Hasher, input []byte) (output []byte) {
    newHmac := hmac.New(hashFunc, hmackey)
    newHmac.Write(input)
    output = newHmac.Sum(nil)

    return
}

func byteceil(size int) int {
    return (size + 7) / 8
}
