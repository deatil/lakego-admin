package sm9

import (
    "io"
    "math/big"
    "crypto/subtle"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/padding"
    "github.com/deatil/go-cryptobin/hash/sm3"
)

// hash implements H1(Z,n) or H2(Z,n) in sm9 algorithm.
func hash(z []byte, n *big.Int, h hashMode) *big.Int {
    var ha [64]byte
    var countBytes [4]byte
    var ct uint32 = 1

    md := sm3.New()

    binary.BigEndian.PutUint32(countBytes[:], ct)
    md.Write([]byte{byte(h)})
    md.Write(z)
    md.Write(countBytes[:])
    copy(ha[:], md.Sum(nil))

    md.Reset()
    ct++

    binary.BigEndian.PutUint32(countBytes[:], ct)
    md.Write([]byte{byte(h)})
    md.Write(z)
    md.Write(countBytes[:])
    copy(ha[sm3.Size:], md.Sum(nil))

    bn := new(big.Int).SetBytes(ha[:40])
    one := big.NewInt(1)

    nMinus1 := new(big.Int).Sub(n, one)

    bn.Mod(bn, nMinus1)
    bn.Add(bn, one)

    return bn
}

// generate rand numbers in [1,n-1].
func randFieldElement(rand io.Reader, n *big.Int) (k *big.Int, err error) {
    one := big.NewInt(1)
    b := make([]byte, 256/8+8)

    _, err = io.ReadFull(rand, b)
    if err != nil {
        return
    }

    k = new(big.Int).SetBytes(b)
    nMinus1 := new(big.Int).Sub(n, one)
    k.Mod(k, nMinus1)

    return
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

func Equal(b1, b2 []byte) bool {
    return subtle.ConstantTimeCompare(b1, b2) == 1
}

// ===============

var newPadding = padding.NewPKCS7()

// 明文补码算法
func pkcs7Padding(text []byte, blockSize int) []byte {
    return newPadding.Padding(text, blockSize)
}

// 明文减码算法
func pkcs7UnPadding(src []byte) ([]byte, error) {
    return newPadding.UnPadding(src)
}
