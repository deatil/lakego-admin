package sm9

import (
    "io"
    "math"
    "math/big"
    "crypto/subtle"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool"
    "github.com/deatil/go-cryptobin/hash/sm3"
)

// hash implements H1(Z,n) or H2(Z,n) in sm9 algorithm.
func hash(z []byte, n *big.Int, h hashMode) *big.Int {
    // counter
    ct := 1

    hlen := 8 * int(math.Ceil(float64(5*n.BitLen()/32)))
    count := int(math.Ceil(float64(hlen/256)))

    var ha []byte
    for i := 0; i < count; i++ {
        msg := append([]byte{byte(h)}, z...)
        buf := make([]byte, 4)

        binary.BigEndian.PutUint32(buf, uint32(ct))
        msg = append(msg, buf...)
        hai := sm3.Sum(msg)
        ct++

        if float64(hlen)/256 == float64(int64(hlen/256)) && i == int(math.Ceil(float64(hlen/256)))-1 {
            ha = append(ha, hai[:(hlen-256*int(math.Floor(float64(hlen/256))))/32]...)
        } else {
            ha = append(ha, hai[:]...)
        }
    }

    bn := new(big.Int).SetBytes(ha)
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

// ===============

var newPadding = tool.NewPadding()

// 明文补码算法
func pkcs7Padding(text []byte, blockSize int) []byte {
    return newPadding.PKCS7Padding(text, blockSize)
}

// 明文减码算法
func pkcs7UnPadding(src []byte) ([]byte, error) {
    return newPadding.PKCS7UnPadding(src)
}
