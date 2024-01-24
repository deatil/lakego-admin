package sm2

import (
    "errors"
    "math/big"
    "encoding/asn1"
)

// 拼接编码
func marshalBytes(c []byte, mode Mode) []byte {
    switch mode {
        case C1C2C3:
            c1 := make([]byte, 64)
            c2 := make([]byte, len(c) - 96)
            c3 := make([]byte, 32)

            copy(c1, c[:64])   // x1, y1
            copy(c3, c[64:96]) // hash
            copy(c2, c[96:])   // 密文

            ct := []byte{}
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

func unmarshalBytes(data []byte, mode Mode) ([]byte, error) {
    typ := data[0]
    if typ != byte(0x04) {
        return nil, errors.New("sm2: encrypt data is error.")
    }

    switch mode {
        case C1C2C3:
            data = data[1:]
            c1 := make([]byte, 64)
            c2 := make([]byte, len(data) - 96)
            c3 := make([]byte, 32)

            copy(c1, data[:64])               // x1, y1
            copy(c2, data[64:len(data) - 32]) // 密文
            copy(c3, data[len(data) - 32:])   // hash

            c := []byte{}
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
func marshalASN1(data []byte, mode Mode) ([]byte, error) {
    if mode == C1C2C3 {
        return marshalASN1Old(data)
    }

    return marshalASN1New(data)
}

func unmarshalASN1(data []byte, mode Mode) ([]byte, error) {
    if mode == C1C2C3 {
        return unmarshalASN1Old(data)
    }

    return unmarshalASN1New(data)
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
func marshalASN1New(data []byte) ([]byte, error) {
    x := new(big.Int).SetBytes(data[:32])
    y := new(big.Int).SetBytes(data[32:64])

    hash       := data[64:96]
    cipherText := data[96:]

    return asn1.Marshal(cipherASN1New{x, y, hash, cipherText})
}

// sm2 密文 asn.1 编码格式转 C1|C3|C2 拼接格式
func unmarshalASN1New(b []byte) ([]byte, error) {
    var data cipherASN1New
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
func marshalASN1Old(data []byte) ([]byte, error) {
    x := new(big.Int).SetBytes(data[:32])
    y := new(big.Int).SetBytes(data[32:64])

    hash       := data[64:96]
    cipherText := data[96:]

    return asn1.Marshal(cipherASN1Old{x, y, cipherText, hash})
}

// sm2 密文 asn.1 编码格式转 C1|C3|C2 拼接格式
func unmarshalASN1Old(b []byte) ([]byte, error) {
    var data cipherASN1Old
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

    return c, nil
}

