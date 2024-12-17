package pkcs7

import (
    "errors"
    "encoding/pem"
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

    return pem.EncodeToMemory(keyBlock)
}

// 解析 pkcs7 pem 数据
func ParsePkcs7Pem(data []byte) ([]byte, error) {
    var block *pem.Block
    if block, _ = pem.Decode(data); block == nil {
        return nil, errors.New("go-cryptobin/pkcs7: data is not pem")
    }

    return block.Bytes, nil
}
