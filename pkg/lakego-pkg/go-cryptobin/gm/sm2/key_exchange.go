package sm2

import (
    "bytes"
    "errors"
    "math/big"

    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/kdf/smkdf"
    "github.com/deatil/go-cryptobin/tool/alias"
)

// KeyExchangeB 协商第二部，用户B调用， 返回共享密钥k
func KeyExchangeB(klen int, ida, idb []byte, priB *PrivateKey, pubA *PublicKey, rpri *PrivateKey, rpubA *PublicKey) (k, s1, s2 []byte, err error) {
    return keyExchange(klen, ida, idb, priB, pubA, rpri, rpubA, false)
}

// KeyExchangeA 协商第二部，用户A调用，返回共享密钥k
func KeyExchangeA(klen int, ida, idb []byte, priA *PrivateKey, pubB *PublicKey, rpri *PrivateKey, rpubB *PublicKey) (k, s1, s2 []byte, err error) {
    return keyExchange(klen, ida, idb, priA, pubB, rpri, rpubB, true)
}

// keyExchange 为SM2密钥交换算法的第二部和第三步复用部分，协商的双方均调用此函数计算共同的字节串
// klen: 密钥长度
// ida, idb: 协商双方的标识，ida为密钥协商算法发起方标识，idb为响应方标识
// pri: 函数调用者的密钥
// pub: 对方的公钥
// rpri: 函数调用者生成的临时SM2密钥
// rpub: 对方发来的临时SM2公钥
// thisIsA: 如果是A调用，文档中的协商第三步，设置为true，否则设置为false
// 返回 k 为klen长度的字节串
func keyExchange(klen int, ida, idb []byte, pri *PrivateKey, pub *PublicKey, rpri *PrivateKey, rpub *PublicKey, thisISA bool) (k, s1, s2 []byte, err error) {
    curve := P256()
    N := curve.Params().N

    x2hat := keXHat(rpri.PublicKey.X)
    x2rb := new(big.Int).Mul(x2hat, rpri.D)

    tbt := new(big.Int).Add(pri.D, x2rb)
    tb := new(big.Int).Mod(tbt, N)

    if !curve.IsOnCurve(rpub.X, rpub.Y) {
        err = errors.New("go-cryptobin/sm2: Ra not on curve")
        return
    }

    x1hat := keXHat(rpub.X)
    ramx1, ramy1 := curve.ScalarMult(rpub.X, rpub.Y, x1hat.Bytes())
    vxt, vyt := curve.Add(pub.X, pub.Y, ramx1, ramy1)

    vx, vy := curve.ScalarMult(vxt, vyt, tb.Bytes())
    pza := pub
    if thisISA {
        pza = &pri.PublicKey
    }

    za, err := CalculateZA(pza, ida)
    if err != nil {
        return
    }

    zero := new(big.Int)
    if vx.Cmp(zero) == 0 || vy.Cmp(zero) == 0 {
        err = errors.New("go-cryptobin/sm2: V is infinite")
    }

    pzb := pub
    if !thisISA {
        pzb = &pri.PublicKey
    }

    zb, err := CalculateZA(pzb, idb)

    kk := make([]byte, 0)
    kk = append(kk, vx.Bytes()...)
    kk = append(kk, vy.Bytes()...)
    kk = append(kk, za...)
    kk = append(kk, zb...)

    k = smkdf.Key(sm3.New, kk, klen)

    if alias.ConstantTimeAllZero(k) {
        err = errors.New("go-cryptobin/sm2: zero key")
        return
    }

    h1 := bytesCombine(vx.Bytes(), za, zb, rpub.X.Bytes(), rpub.Y.Bytes(), rpri.X.Bytes(), rpri.Y.Bytes())
    if !thisISA {
        h1 = bytesCombine(vx.Bytes(), za, zb, rpri.X.Bytes(), rpri.Y.Bytes(), rpub.X.Bytes(), rpub.Y.Bytes())
    }

    hash := sm3.Sum(h1)

    h2 := bytesCombine([]byte{0x02}, vy.Bytes(), hash[:])
    S1 := sm3.Sum(h2)

    h3 := bytesCombine([]byte{0x03}, vy.Bytes(), hash[:])
    S2 := sm3.Sum(h3)

    return k, S1[:], S2[:], nil
}

// keXHat 计算 x = 2^w + (x & (2^w-1))
// 密钥协商算法辅助函数
func keXHat(x *big.Int) (xul *big.Int) {
    buf := x.Bytes()
    for i := 0; i < len(buf)-16; i++ {
        buf[i] = 0
    }
    if len(buf) >= 16 {
        c := buf[len(buf)-16]
        buf[len(buf)-16] = c & 0x7f
    }

    r := new(big.Int).SetBytes(buf)

    w2 := new(big.Int).SetBytes([]byte{
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    })

    return r.Add(r, w2)
}

func bytesCombine(pBytes ...[]byte) []byte {
    num := len(pBytes)

    s := make([][]byte, num)

    for index := 0; index < num; index++ {
        s[index] = pBytes[index]
    }

    sep := []byte("")

    return bytes.Join(s, sep)
}
