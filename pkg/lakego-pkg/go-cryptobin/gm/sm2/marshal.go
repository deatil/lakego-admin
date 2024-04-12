package sm2

import (
    "errors"
    "math/big"
    "encoding/asn1"
    "crypto/elliptic"
)

type sm2Signature struct {
    R, S *big.Int
}

func MarshalSignatureASN1(r, s *big.Int) ([]byte, error) {
    return asn1.Marshal(sm2Signature{r, s})
}

func UnmarshalSignatureASN1(sign []byte) (r, s *big.Int, err error) {
    var sm2Sign sm2Signature

    _, err = asn1.Unmarshal(sign, &sm2Sign)
    if err != nil {
        return
    }

    return sm2Sign.R, sm2Sign.S, nil
}

// 拼接编码
func marshalCipherBytes(curve elliptic.Curve, c []byte, mode Mode, h hashFunc) []byte {
    byteLen := (curve.Params().BitSize + 7) / 8
    hashSize := h().Size()

    // C1C3C2 密文结构: x + y + hash + CipherText
    // C1C2C3 密文结构: x + y + CipherText + hash
    switch mode {
        case C1C2C3:
            c1 := make([]byte, 2*byteLen)
            c2 := make([]byte, len(c) - 2*byteLen - hashSize)
            c3 := make([]byte, hashSize)

            copy(c1, c[0:])            // x1, y1
            copy(c3, c[2*byteLen:])    // hash
            copy(c2, c[2*byteLen+hashSize:]) // 密文

            ct := make([]byte, 0)
            ct = append(ct, c1...)
            ct = append(ct, c2...)
            ct = append(ct, c3...)

            return append([]byte{0x04}, ct...)
        case C1C3C2:
            fallthrough
        default:
            return append([]byte{0x04}, c...)
    }
}

func unmarshalCipherBytes(curve elliptic.Curve, data []byte, mode Mode, h hashFunc) ([]byte, error) {
    typ := data[0]
    if typ != byte(0x04) {
        return nil, errors.New("cryptobin/sm2: encrypted data is error and misss prefix '4'.")
    }

    hashSize := h().Size()

    byteLen := (curve.Params().BitSize + 7) / 8
    if len(data) < 2*byteLen + hashSize {
        return nil, errors.New("cryptobin/sm2: encrypt data is too short.")
    }

    switch mode {
        case C1C2C3:
            data = data[1:]

            c1 := make([]byte, 2*byteLen)
            c2 := make([]byte, len(data) - 2*byteLen - hashSize)
            c3 := make([]byte, hashSize)

            copy(c1, data[0:])              // x1, y1
            copy(c2, data[2*byteLen:])      // 密文
            copy(c3, data[len(data) - hashSize:]) // hash

            c := make([]byte, 0)
            c = append(c, c1...)
            c = append(c, c3...)
            c = append(c, c2...)

            data = c
        case C1C3C2:
            fallthrough
        default:
            data = data[1:]
    }

    return data, nil
}

// asn.1 编码
func marshalCipherASN1(curve elliptic.Curve, data []byte, mode Mode, h hashFunc) ([]byte, error) {
    hashSize := h().Size()

    if mode == C1C2C3 {
        return marshalCipherASN1Old(curve, data, hashSize)
    }

    return marshalCipherASN1New(curve, data, hashSize)
}

func unmarshalCipherASN1(curve elliptic.Curve, data []byte, mode Mode) ([]byte, error) {
    if mode == C1C2C3 {
        return unmarshalCipherASN1Old(curve, data)
    }

    return unmarshalCipherASN1New(curve, data)
}

// c1c3c2 格式
type cipherASN1New struct {
    XCoordinate *big.Int
    YCoordinate *big.Int
    HASH        []byte
    CipherText  []byte
}

// sm2 密文转 asn.1 编码格式
// sm2 密文结构: x + y + hash + CipherText
func marshalCipherASN1New(curve elliptic.Curve, data []byte, hashSize int) ([]byte, error) {
    byteLen := (curve.Params().BitSize + 7) / 8

    x := new(big.Int).SetBytes(data[:byteLen])
    y := new(big.Int).SetBytes(data[byteLen:2*byteLen])

    hash       := data[2*byteLen:2*byteLen+hashSize]
    cipherText := data[2*byteLen+hashSize:]

    return asn1.Marshal(cipherASN1New{x, y, hash, cipherText})
}

// sm2 密文 asn.1 编码格式转 C1|C3|C2 拼接格式
func unmarshalCipherASN1New(curve elliptic.Curve, b []byte) ([]byte, error) {
    var data cipherASN1New
    _, err := asn1.Unmarshal(b, &data)
    if err != nil {
        return nil, err
    }

    xBuf := bigIntToBytes(curve, data.XCoordinate)
    yBuf := bigIntToBytes(curve, data.YCoordinate)

    c := []byte{}
    c = append(c, xBuf...)            // x分量
    c = append(c, yBuf...)            // y分量
    c = append(c, data.HASH...)       // hash
    c = append(c, data.CipherText...) // cipherText

    return c, nil
}

// c1c2c3 格式
type cipherASN1Old struct {
    XCoordinate *big.Int
    YCoordinate *big.Int
    CipherText  []byte
    HASH        []byte
}

// sm2 密文转 asn.1 编码格式
// sm2 密文结构: x + y + CipherText + hash
func marshalCipherASN1Old(curve elliptic.Curve, data []byte, hashSize int) ([]byte, error) {
    byteLen := (curve.Params().BitSize + 7) / 8

    x := new(big.Int).SetBytes(data[:byteLen])
    y := new(big.Int).SetBytes(data[byteLen:2*byteLen])

    hash       := data[2*byteLen:2*byteLen+hashSize]
    cipherText := data[2*byteLen+hashSize:]

    return asn1.Marshal(cipherASN1Old{x, y, cipherText, hash})
}

// sm2 密文 asn.1 编码格式转 C1|C3|C2 拼接格式
func unmarshalCipherASN1Old(curve elliptic.Curve, b []byte) ([]byte, error) {
    var data cipherASN1Old
    _, err := asn1.Unmarshal(b, &data)
    if err != nil {
        return nil, err
    }

    xBuf := bigIntToBytes(curve, data.XCoordinate)
    yBuf := bigIntToBytes(curve, data.YCoordinate)

    c := []byte{}
    c = append(c, xBuf...)            // x分量
    c = append(c, yBuf...)            // y分量
    c = append(c, data.HASH...)       // hash
    c = append(c, data.CipherText...) // cipherText

    return c, nil
}

