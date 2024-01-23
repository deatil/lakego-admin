package sm2

import (
    "io"
    "bytes"
    "math/big"
    "encoding/asn1"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/gm/sm2/curve"
)

func Decompress(a []byte) *PublicKey {
    c := P256()

    x, y := curve.UnmarshalCompressed(c, a)

    return &PublicKey{
        Curve: c,
        X:     x,
        Y:     y,
    }
}

func Compress(a *PublicKey) []byte {
    return curve.MarshalCompressed(a.X, a.Y)
}

func SignDigitToSignData(r, s *big.Int) ([]byte, error) {
    return asn1.Marshal(sm2Signature{r, s})
}

func SignDataToSignDigit(sign []byte) (*big.Int, *big.Int, error) {
    var sm2Sign sm2Signature

    _, err := asn1.Unmarshal(sign, &sm2Sign)
    if err != nil {
        return nil, nil, err
    }
    return sm2Sign.R, sm2Sign.S, nil
}

type zr struct {
    io.Reader
}

func (z *zr) Read(dst []byte) (n int, err error) {
    for i := range dst {
        dst[i] = 0
    }

    return len(dst), nil
}

var zeroReader = &zr{}

func kdf(length int, x ...[]byte) ([]byte, bool) {
    var c []byte

    ct := 1
    h := sm3.New()

    for i, j := 0, (length+31)/32; i < j; i++ {
        h.Reset()
        for _, xx := range x {
            h.Write(xx)
        }

        h.Write(intToBytes(ct))

        hash := h.Sum(nil)
        if i+1 == j && length%32 != 0 {
            c = append(c, hash[:length%32]...)
        } else {
            c = append(c, hash...)
        }

        ct++
    }

    for i := 0; i < length; i++ {
        if c[i] != 0 {
            return c, true
        }
    }

    return c, false
}

func intToBytes(x int) []byte {
    var buf = make([]byte, 4)

    binary.BigEndian.PutUint32(buf, uint32(x))
    return buf
}

// zero padding
func zeroPadding(text []byte, size int) []byte {
    if size < 1 {
        return text
    }

    n := len(text)

    if n == size {
        return text
    }

    if n < size {
        r := bytes.Repeat([]byte("0"), size - n)
        return append(r, text...)
    }

    return text[n-size:]
}

type sm2ASN1 struct {
    XCoordinate *big.Int
    YCoordinate *big.Int
    HASH        []byte
    CipherText  []byte
}

// sm2 密文转 asn.1 编码格式
// sm2 密文结构: x + y + hash + CipherText
func ASN1Marshal(data []byte) ([]byte, error) {
    data = data[1:]

    x := new(big.Int).SetBytes(data[:32])
    y := new(big.Int).SetBytes(data[32:64])

    hash       := data[64:96]
    cipherText := data[96:]

    return asn1.Marshal(sm2ASN1{x, y, hash, cipherText})
}

// sm2 密文 asn.1 编码格式转 C1|C3|C2 拼接格式
func ASN1Unmarshal(b []byte) ([]byte, error) {
    var data sm2ASN1
    _, err := asn1.Unmarshal(b, &data)
    if err != nil {
        return nil, err
    }

    x := data.XCoordinate.Bytes()
    y := data.YCoordinate.Bytes()

    hash       := data.HASH
    cipherText := data.CipherText

    x = zeroPadding(x, 32)
    y = zeroPadding(y, 32)

    c := []byte{}
    c = append(c, x...)          // x分量
    c = append(c, y...)          // y分量
    c = append(c, hash...)       // hash
    c = append(c, cipherText...) // cipherText

    return append([]byte{0x04}, c...), nil
}

type sm2C1C2C3ASN1 struct {
    XCoordinate *big.Int
    YCoordinate *big.Int
    CipherText  []byte
    HASH        []byte
}

// sm2 密文转 asn.1 编码格式
// sm2 密文结构: x + y + CipherText + hash
func ASN1MarshalC1C2C3(data []byte) ([]byte, error) {
    data = data[1:]

    x := new(big.Int).SetBytes(data[:32])
    y := new(big.Int).SetBytes(data[32:64])

    hash       := data[64:96]
    cipherText := data[96:]

    return asn1.Marshal(sm2C1C2C3ASN1{x, y, cipherText, hash})
}

// sm2 密文 asn.1 编码格式转 C1|C3|C2 拼接格式
func ASN1UnmarshalC1C2C3(b []byte) ([]byte, error) {
    var data sm2C1C2C3ASN1
    _, err := asn1.Unmarshal(b, &data)
    if err != nil {
        return nil, err
    }

    x := data.XCoordinate.Bytes()
    y := data.YCoordinate.Bytes()

    hash       := data.HASH
    cipherText := data.CipherText

    x = zeroPadding(x, 32)
    y = zeroPadding(y, 32)

    c := []byte{}
    c = append(c, x...)          // x分量
    c = append(c, y...)          // y分量
    c = append(c, hash...)       // hash
    c = append(c, cipherText...) // cipherText

    return append([]byte{0x04}, c...), nil
}

