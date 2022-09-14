package jceks

import (
    "hash"
    "crypto/sha1"
    "crypto/x509/pkix"
    "encoding/asn1"
)

func getJksPreKeyedHash(password []byte) hash.Hash {
    md := sha1.New()

    buf := charsToBytes(password)

    md.Write(buf)

    // Yes, "Mighty Aphrodite" is a constant used by this method.
    md.Write([]byte("Mighty Aphrodite"))

    return md
}

func charsToBytes(password []byte) []byte {
    buf := make([]byte, len(password)*2)

    j := 0
    for i := 0; i < len(password); i++ {
        buf[j] = byte(password[i] >> 8)
        j++

        buf[j] = byte(password[i])
        j++
    }

    return buf
}

// 加密结构图
type encryptedPrivateKeyInfo struct {
    Algo          pkix.AlgorithmIdentifier
    EncryptedData []byte
}

// 加密数据
func EncryptedPrivateKeyInfo(algorithm asn1.ObjectIdentifier, data []byte) ([]byte, error) {
    var eData encryptedPrivateKeyInfo
    eData.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  algorithm,
        Parameters: asn1.RawValue{
            Tag: asn1.TagNull,
        },
    }
    eData.EncryptedData = data

    return asn1.Marshal(eData)
}

// 解密数据
func DecryptedPrivateKeyInfo(data []byte) ([]byte, error) {
    var eData encryptedPrivateKeyInfo
    err := unmarshal(data, &eData)
    if err != nil {
        return nil, err
    }

    return eData.EncryptedData, nil
}

func isInArray[T any](item string, items map[string]T) bool {
    for name, _ := range items {
        if name == item {
            return true
        }
    }

    return false
}

func isInSlice(item string, items []string) bool {
    for _, name := range items {
        if name == item {
            return true
        }
    }

    return false
}
