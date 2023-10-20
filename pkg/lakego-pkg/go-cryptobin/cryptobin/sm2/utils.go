package sm2

import(
    "math/big"
    "encoding/asn1"
)

// ASN1 结构
type sm2C1C2C3Cipher struct {
    XCoordinate *big.Int
    YCoordinate *big.Int
    CipherText  []byte
    HASH        []byte
}

/**
 * sm2密文转asn.1编码格式
 * sm2密文结构如下:
 *  x
 *  y
 *  CipherText
 *  hash
 */
func cipherC1C2C3Marshal(data []byte) ([]byte, error) {
    data = data[1:]

    x := new(big.Int).SetBytes(data[:32])
    y := new(big.Int).SetBytes(data[32:64])

    cipherText := data[64:len(data) - 32]
    hash := data[len(data) - 32:]

    return asn1.Marshal(sm2C1C2C3Cipher{x, y, cipherText, hash})
}

// sm2密文asn.1编码格式转C1|C2|C3拼接格式
func cipherC1C2C3Unmarshal(data []byte) ([]byte, error) {
    var cipher sm2C1C2C3Cipher
    _, err := asn1.Unmarshal(data, &cipher)
    if err != nil {
        return nil, err
    }

    x := cipher.XCoordinate.Bytes()
    y := cipher.YCoordinate.Bytes()

    hash := cipher.HASH
    if err != nil {
        return nil, err
    }

    cipherText := cipher.CipherText
    if err != nil {
        return nil, err
    }

    if n := len(x); n < 32 {
        x = append(zeroByteSlice()[:32-n], x...)
    }

    if n := len(y); n < 32 {
        y = append(zeroByteSlice()[:32-n], y...)
    }

    c := []byte{}
    c = append(c, x...)          // x分量
    c = append(c, y...)          // y分
    c = append(c, cipherText...) // y分
    c = append(c, hash...)       // x分量

    return append([]byte{0x04}, c...), nil
}

// 32byte
func zeroByteSlice() []byte {
    return []byte{
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    }
}
