package pbes1

import (
    "io"
    "fmt"
    "errors"
    "crypto/x509/pkix"
    "encoding/asn1"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
)

// 结构体数据可以查看以下文档
// RFC5208 at https://tools.ietf.org/html/rfc5208
// RFC5958 at https://tools.ietf.org/html/rfc5958
type encryptedPrivateKeyInfo struct {
    EncryptionAlgorithm pkix.AlgorithmIdentifier
    EncryptedData       []byte
}

// 加密 PKCS8 私钥
func EncryptPKCS8PrivateKey(
    rand io.Reader,
    blockType string,
    data []byte,
    password []byte,
    cipher Cipher,
) (*pem.Block, error) {
    if cipher == nil {
        return nil, errors.New("failed to encrypt PEM: unknown cipher")
    }

    if cipher.NeedBmpPassword() {
        var err error
        password, err = BmpStringZeroTerminated(string(password))
        if err != nil {
            return nil, err
        }
    }

    encrypted, marshalledParams, err := cipher.Encrypt(rand, password, data)
    if err != nil {
        return nil, err
    }

    encryptionAlgorithm := pkix.AlgorithmIdentifier{
        Algorithm:  cipher.OID(),
        Parameters: asn1.RawValue{
            FullBytes: marshalledParams,
        },
    }

    // 生成 ans1 数据
    pki := encryptedPrivateKeyInfo{
        EncryptionAlgorithm: encryptionAlgorithm,
        EncryptedData:       encrypted,
    }

    b, err := asn1.Marshal(pki)
    if err != nil {
        return nil, errors.New(err.Error() + " error marshaling encrypted key")
    }

    return &pem.Block{
        Type:  blockType,
        Bytes: b,
    }, nil
}

// 解出 PKCS8 私钥
func DecryptPKCS8PrivateKey(data, password []byte) ([]byte, error) {
    var pki encryptedPrivateKeyInfo
    if _, err := asn1.Unmarshal(data, &pki); err != nil {
        return nil, errors.New(err.Error() + " failed to unmarshal private key")
    }

    cipher, cipherParams, err := parseEncryptionScheme(pki.EncryptionAlgorithm)
    if err != nil {
        return nil, err
    }

    if cipher.NeedBmpPassword() {
        var err error
        password, err = BmpStringZeroTerminated(string(password))
        if err != nil {
            return nil, err
        }
    }

    encryptedKey := pki.EncryptedData

    decryptedKey, err := cipher.Decrypt(password, cipherParams, encryptedKey)
    if err != nil {
        return nil, err
    }

    return decryptedKey, nil
}

// 加密 PKCS8 私钥，不处理密码
func EncryptPKCS8Privatekey(
    rand io.Reader,
    blockType string,
    data []byte,
    password []byte,
    cipher Cipher,
) (*pem.Block, error) {
    if cipher == nil {
        return nil, errors.New("failed to encrypt PEM: unknown cipher")
    }

    encrypted, marshalledParams, err := cipher.Encrypt(rand, password, data)
    if err != nil {
        return nil, err
    }

    encryptionAlgorithm := pkix.AlgorithmIdentifier{
        Algorithm:  cipher.OID(),
        Parameters: asn1.RawValue{
            FullBytes: marshalledParams,
        },
    }

    // 生成 ans1 数据
    pki := encryptedPrivateKeyInfo{
        EncryptionAlgorithm: encryptionAlgorithm,
        EncryptedData:       encrypted,
    }

    b, err := asn1.Marshal(pki)
    if err != nil {
        return nil, errors.New(err.Error() + " error marshaling encrypted key")
    }

    return &pem.Block{
        Type:  blockType,
        Bytes: b,
    }, nil
}

// 解出 PKCS8 私钥，不处理密码
func DecryptPKCS8Privatekey(data, password []byte) ([]byte, error) {
    var pki encryptedPrivateKeyInfo
    if _, err := asn1.Unmarshal(data, &pki); err != nil {
        return nil, errors.New(err.Error() + " failed to unmarshal private key")
    }

    cipher, cipherParams, err := parseEncryptionScheme(pki.EncryptionAlgorithm)
    if err != nil {
        return nil, err
    }

    encryptedKey := pki.EncryptedData

    decryptedKey, err := cipher.Decrypt(password, cipherParams, encryptedKey)
    if err != nil {
        return nil, err
    }

    return decryptedKey, nil
}

// 解出 PEM 块
func DecryptPEMBlock(block *pem.Block, password []byte) ([]byte, error) {
    if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
        return pkcs1.DecryptPEMBlock(block, password)
    }

    // PKCS#8 header defined in RFC7468 section 11
    if block.Type == "ENCRYPTED PRIVATE KEY" {
        return DecryptPKCS8PrivateKey(block.Bytes, password)
    }

    return nil, errors.New("unsupported encrypted PEM")
}

func parseEncryptionScheme(encryptionScheme pkix.AlgorithmIdentifier) (Cipher, []byte, error) {
    oid := encryptionScheme.Algorithm.String()

    newCipher, err := GetCipher(oid)
    if err != nil {
        return nil, nil, fmt.Errorf("go-cryptobin/pkcs8: unsupported cipher (OID: %s)", oid)
    }

    params := encryptionScheme.Parameters.FullBytes

    return newCipher, params, nil
}
