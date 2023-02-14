package crypto

import (
    "strconv"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

/**
 * 对称加密
 *
 * @create 2022-3-19
 * @author deatil
 */
type Cryptobin struct {
    // 数据
    data []byte

    // 密钥
    key []byte

    // 向量
    iv []byte

    // 加密类型
    multiple Multiple

    // 加密模式
    mode Mode

    // 填充模式
    padding Padding

    // 解析后的数据
    parsedData []byte

    // 额外配置
    config *cryptobin_tool.Config

    // 错误
    Errors []error
}

// 补码类型
type Padding uint

func (this Padding) String() string {
    switch this {
        case NoPadding:
            return "NoPadding"
        case ZeroPadding:
            return "ZeroPadding"
        case PKCS5Padding:
            return "PKCS5Padding"
        case PKCS7Padding:
            return "PKCS7Padding"
        case X923Padding:
            return "X923Padding"
        case ISO10126Padding:
            return "ISO10126Padding"
        case ISO7816_4Padding:
            return "ISO7816_4Padding"
        case ISO97971Padding:
            return "ISO97971Padding"
        case TBCPadding:
            return "TBCPadding"
        case PKCS1Padding:
            return "PKCS1Padding"
        default:
            return "unknown padding value " + strconv.Itoa(int(this))
    }
}

const (
    NoPadding Padding = 1 + iota
    ZeroPadding
    PKCS5Padding
    PKCS7Padding
    X923Padding
    ISO10126Padding
    ISO7816_4Padding
    ISO97971Padding
    TBCPadding
    PKCS1Padding
)

// 加密类型
type Multiple uint

func (this Multiple) String() string {
    switch this {
        case Aes:
            return "Aes"
        case Des:
            return "Des"
        case TriDes:
            return "TriDes"
        case Twofish:
            return "Twofish"
        case Blowfish:
            return "Blowfish"
        case Tea:
            return "Tea"
        case Xtea:
            return "Xtea"
        case Cast5:
            return "Cast5"
        case RC2:
            return "RC2"
        case RC4:
            return "RC4"
        case RC5:
            return "RC5"
        case SM4:
            return "SM4"
        case Chacha20:
            return "Chacha20"
        case Chacha20poly1305:
            return "Chacha20poly1305"
        case Chacha20poly1305X:
            return "Chacha20poly1305X"
        case Xts:
            return "Xts"
        default:
            return "unknown multiple value " + strconv.Itoa(int(this))
    }
}

const (
    Aes Multiple = 1 + iota
    Des
    TriDes
    Twofish
    Blowfish
    Tea
    Xtea
    Cast5
    RC2
    RC4
    RC5
    SM4
    Chacha20
    Chacha20poly1305
    Chacha20poly1305X
    Xts
)

// 加密模式
type Mode uint

func (this Mode) String() string {
    switch this {
        case ECB:
            return "ECB"
        case CBC:
            return "CBC"
        case CFB:
            return "CFB"
        case CFB8:
            return "CFB8"
        case OFB:
            return "OFB"
        case OFB8:
            return "OFB8"
        case CTR:
            return "CTR"
        case GCM:
            return "GCM"
        case CCM:
            return "CCM"
        default:
            return "unknown mode value " + strconv.Itoa(int(this))
    }
}

const (
    ECB  Mode = 1 + iota
    CBC
    CFB
    CFB8
    OFB
    OFB8
    CTR
    GCM
    CCM
)

