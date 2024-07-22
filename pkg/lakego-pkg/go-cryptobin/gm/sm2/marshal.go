package sm2

import (
    "errors"
    "math/big"
    "encoding/asn1"
    "crypto/elliptic"
)

// 拼接编码
func MarshalSignatureBytes(curve elliptic.Curve, r, s *big.Int) ([]byte, error) {
    byteLen := (curve.Params().BitSize + 7) / 8

    buf := make([]byte, 2*byteLen)

    r.FillBytes(buf[      0:  byteLen])
    s.FillBytes(buf[byteLen:2*byteLen])

    return buf, nil
}

func UnmarshalSignatureBytes(curve elliptic.Curve, sign []byte) (r, s *big.Int, err error) {
    byteLen := (curve.Params().BitSize + 7) / 8
    if len(sign) != 2*byteLen {
        err = errors.New("cryptobin/sm2: incorrect signature")
        return
    }

    r = new(big.Int).SetBytes(sign[      0:  byteLen])
    s = new(big.Int).SetBytes(sign[byteLen:2*byteLen])

    return
}

type sm2Signature struct {
    R, S *big.Int
}

// asn.1 编码
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
func marshalCipherBytes(c encryptedData, mode Mode) []byte {
    // C1C3C2 密文结构: x + y + hash + CipherText
    // C1C2C3 密文结构: x + y + CipherText + hash
    switch mode {
        case C1C2C3:
            ct := []byte{0x04}
            ct = append(ct, c.XCoordinate...)
            ct = append(ct, c.YCoordinate...)
            ct = append(ct, c.CipherText...)
            ct = append(ct, c.Hash...)

            return ct
        case C1C3C2:
            fallthrough
        default:
            ct := []byte{0x04}
            ct = append(ct, c.XCoordinate...)
            ct = append(ct, c.YCoordinate...)
            ct = append(ct, c.Hash...)
            ct = append(ct, c.CipherText...)

            return ct
    }
}

func unmarshalCipherBytes(curve elliptic.Curve, data []byte, mode Mode, h hashFunc) (encryptedData, error) {
    typ := data[0]
    if typ != byte(0x04) {
        return encryptedData{}, errors.New("cryptobin/sm2: encrypted data is error and miss prefix '4'.")
    }

    hashSize := h().Size()

    byteLen := (curve.Params().BitSize + 7) / 8
    if len(data) < 2*byteLen + hashSize {
        return encryptedData{}, errors.New("cryptobin/sm2: encrypt data is too short.")
    }

    data = data[1:]

    switch mode {
        case C1C2C3:
            c1 := data[:2*byteLen]
            c2 := data[2*byteLen:len(data)-hashSize]
            c3 := data[len(data)-hashSize:]

            return encryptedData{
                XCoordinate: c1[:byteLen], // x分量
                YCoordinate: c1[byteLen:], // y分量
                Hash:        c3,           // hash
                CipherText:  c2,           // cipherText
            }, nil
        case C1C3C2:
            fallthrough
        default:
            c1 := data[:2*byteLen]
            c3 := data[2*byteLen:2*byteLen+hashSize]
            c2 := data[2*byteLen+hashSize:]

            return encryptedData{
                XCoordinate: c1[:byteLen], // x分量
                YCoordinate: c1[byteLen:], // y分量
                Hash:        c3,           // hash
                CipherText:  c2,           // cipherText
            }, nil
    }
}

// asn.1 编码
func marshalCipherASN1(data encryptedData, mode Mode) ([]byte, error) {
    if mode == C1C2C3 {
        return marshalCipherASN1Old(data)
    }

    return marshalCipherASN1New(data)
}

func unmarshalCipherASN1(curve elliptic.Curve, data []byte, mode Mode) (encryptedData, error) {
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
func marshalCipherASN1New(data encryptedData) ([]byte, error) {
    return asn1.Marshal(cipherASN1New{
        XCoordinate: bytesToBigInt(data.XCoordinate),
        YCoordinate: bytesToBigInt(data.YCoordinate),
        HASH:        data.Hash,
        CipherText:  data.CipherText,
    })
}

// sm2 密文 asn.1 编码格式转 C1|C3|C2 拼接格式
func unmarshalCipherASN1New(curve elliptic.Curve, b []byte) (encryptedData, error) {
    var data cipherASN1New
    _, err := asn1.Unmarshal(b, &data)
    if err != nil {
        return encryptedData{}, err
    }

    x := bigIntToBytes(curve, data.XCoordinate)
    y := bigIntToBytes(curve, data.YCoordinate)

    return encryptedData{
        XCoordinate: x, // x分量
        YCoordinate: y, // y分量
        Hash:        data.HASH,       // hash
        CipherText:  data.CipherText, // cipherText
    }, nil
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
func marshalCipherASN1Old(data encryptedData) ([]byte, error) {
    return asn1.Marshal(cipherASN1Old{
        XCoordinate: bytesToBigInt(data.XCoordinate),
        YCoordinate: bytesToBigInt(data.YCoordinate),
        CipherText:  data.CipherText,
        HASH:        data.Hash,
    })
}

// sm2 密文 asn.1 编码格式转 C1|C3|C2 拼接格式
func unmarshalCipherASN1Old(curve elliptic.Curve, b []byte) (encryptedData, error) {
    var data cipherASN1Old
    _, err := asn1.Unmarshal(b, &data)
    if err != nil {
        return encryptedData{}, err
    }

    x := bigIntToBytes(curve, data.XCoordinate)
    y := bigIntToBytes(curve, data.YCoordinate)

    return encryptedData{
        XCoordinate: x, // x分量
        YCoordinate: y, // y分量
        CipherText:  data.CipherText, // cipherText
        Hash:        data.HASH,       // hash
    }, nil
}

