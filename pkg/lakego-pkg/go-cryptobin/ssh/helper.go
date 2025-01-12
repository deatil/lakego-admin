package ssh

import (
    "errors"
    "encoding/pem"
)

// Cipher map
var cipherMap = map[string]Cipher{
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

// get Cipher from name
func GetCipherFromName(name string) Cipher {
    if data, ok := cipherMap[name]; ok {
        return data
    }

    return cipherMap["AES256CTR"]
}

// Encode SSHKey to pem
func EncodeSSHKeyToPem(keyBlock *pem.Block) []byte {
    keyData := pem.EncodeToMemory(keyBlock)

    return keyData
}

// Parse SSHKey Pem data
func ParseSSHKeyPem(data []byte) ([]byte, error) {
    var block *pem.Block
    if block, _ = pem.Decode(data); block == nil {
        return nil, errors.New("ssh: data is not pem")
    }

    return block.Bytes, nil
}
