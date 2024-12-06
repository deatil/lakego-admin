package pem

import(
    "errors"
    "encoding/pem"
)

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

// BlockType 列表
var PemBlockTypeMap = map[string]string{
    "pri_key":    "PRIVATE KEY",
    "en_pri_key": "ENCRYPTED PRIVATE KEY",
    "pub_key":    "PUBLIC KEY",

    "ec_pri_key":  "EC PRIVATE KEY",
    "dsa_pri_key": "DSA PRIVATE KEY",
    "rsa_pri_key": "RSA PRIVATE KEY",
}

// 获取 PEM 类型
func GetPEMType(name string) string {
    if data, ok := PemBlockTypeMap[name]; ok {
        return data
    }

    return ""
}

// 编码字节数据为 PEM 证书
func EncodeToPEM(data []byte, blockType string) []byte {
    block := &pem.Block{
        Type:  blockType,
        Bytes: data,
    }

    return pem.EncodeToMemory(block)
}

// 解析 PEM 证书
func ParsePEM(data []byte) ([]byte, error) {
    var block *pem.Block
    if block, _ = pem.Decode(data); block == nil {
        return nil, errors.New("pem: data is not pem")
    }

    return block.Bytes, nil
}
