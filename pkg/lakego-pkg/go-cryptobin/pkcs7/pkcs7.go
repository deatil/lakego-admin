package pkcs7

import (
    "errors"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs7/sign"
    "github.com/deatil/go-cryptobin/pkcs7/encrypt"
)

var (
    // 添加签名数据
    NewSignedData = sign.NewSignedData

    // DegenerateCertificate
    DegenerateCertificate = sign.DegenerateCertificate

    // 加密
    Encrypt = encrypt.Encrypt

    // 加密
    EncryptUsingPSK = encrypt.EncryptUsingPSK

    // 解密
    Decrypt = encrypt.Decrypt

    // 解密
    DecryptUsingPSK = encrypt.DecryptUsingPSK
)

type (
    // 额外信息
    SignerInfoConfig = sign.SignerInfoConfig
)

// 编码到 pem
// pemType = [PKCS7 | ENCRYPTED PKCS7]
func EncodePkcs7ToPem(data []byte, pemType string) []byte {
    if pemType == "" {
        pemType = "PKCS7"
    }

    keyBlock := &pem.Block{
        Type: pemType,
        Bytes: data,
    }

    keyData := pem.EncodeToMemory(keyBlock)

    return keyData
}

// 解析 pkcs7 pem 数据
func ParsePkcs7Pem(data []byte) ([]byte, error) {
    var block *pem.Block
    if block, _ = pem.Decode(data); block == nil {
        return nil, errors.New("pkcs7: data is not pem")
    }

    keyData := block.Bytes

    return keyData, nil
}
