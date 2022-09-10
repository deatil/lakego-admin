package tool

import(
    "errors"
    "encoding/pem"
)

// BlockType 列表
var PemBlockTypeMap = map[string]string{
    "pri_key":    "PRIVATE KEY",
    "en_pri_key": "ENCRYPTED PRIVATE KEY",
    "pub_key":    "PUBLIC KEY",

    "ec_pri_key":  "EC PRIVATE KEY",
    "dsa_pri_key": "DSA PRIVATE KEY",
    "rsa_pri_key": "RSA PRIVATE KEY",
}

type (
    // Block
    Block = pem.Block
)

var (
    // 编码
    // Encode(out io.Writer, b *Block) error
    Encode = pem.Encode

    // 编码
    // EncodeToMemory(b *Block) []byte
    EncodeToMemory = pem.EncodeToMemory

    // 解码
    // Decode(data []byte) (p *Block, rest []byte)
    Decode = pem.Decode
)

// 获取 BlockType 类型
func GetBlockTypeFromName(name string) string {
    if data, ok := PemBlockTypeMap[name]; ok {
        return data
    }

    return ""
}

// der 证书编码为 pem 证书
func EncodeDerToPem(data []byte, blockType string) []byte {
    block := &pem.Block{
        Type:  blockType,
        Bytes: data,
    }

    return pem.EncodeToMemory(block)
}

// 解析 pem 证书为 der 证书
func ParsePemToDer(data []byte) ([]byte, error) {
    var block *pem.Block
    if block, _ = pem.Decode(data); block == nil {
        return nil, errors.New("pem: data is not pem")
    }

    keyData := block.Bytes

    return keyData, nil
}
