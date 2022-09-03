package ssh

import (
    "errors"
    "encoding/pem"
)

// Cipher 列表
var CipherMap = map[string]Cipher{
    "DESEDE3CBC":       DESEDE3CBC,
    "BlowfishCBC":      BlowfishCBC,
    "Chacha20poly1305": Chacha20poly1305,

    "Cast128CBC": Cast128CBC,

    "AES128CBC": AES128CBC,
    "AES192CBC": AES192CBC,
    "AES256CBC": AES256CBC,

    "AES128CTR": AES128CTR,
    "AES192CTR": AES192CTR,
    "AES256CTR": AES256CTR,

    "AES128GCM": AES128GCM,
    "AES256GCM": AES256GCM,

    "Arcfour":    Arcfour,
    "Arcfour128": Arcfour128,
    "Arcfour256": Arcfour256,

    "SM4CBC": SM4CBC,
    "SM4CTR": SM4CTR,
}

// 获取 Cipher 类型
func GetCipherFromName(name string) Cipher {
    if data, ok := CipherMap[name]; ok {
        return data
    }

    return CipherMap["AES256CTR"]
}

// 编码到 pem
func EncodeSSHKeyToPem(keyBlock *pem.Block) []byte {
    keyData := pem.EncodeToMemory(keyBlock)

    return keyData
}

// 解析 pem 数据
func ParseSSHKeyPem(data []byte) ([]byte, error) {
    var block *pem.Block
    if block, _ = pem.Decode(data); block == nil {
        return nil, errors.New("ssh: data is not pem")
    }

    keyData := block.Bytes

    return keyData, nil
}
