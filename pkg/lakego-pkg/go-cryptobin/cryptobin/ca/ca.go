package ca

/**
 * CA
 *
 * @create 2022-7-22
 * @author deatil
 */
type CA struct {
    // 证书数据
    // 可用 [*x509.Certificate | *sm2X509.Certificate]
    cert any

    // 证书请求
    // 可用 [*x509.CertificateRequest | *sm2X509.CertificateRequest]
    certRequest any

    // 私钥
    // 可用 [*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey | *sm2.PrivateKey]
    privateKey any

    // 公钥
    // 可用 [*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey | *sm2.PublicKey]
    publicKey any

    // [私钥/公钥/cert]数据
    keyData []byte

    // 错误
    Errors []error
}

// 构造函数
func NewCA() CA {
    return CA{
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() CA {
    return NewCA()
}

var (
    // 默认
    defaultCA = NewCA()
)
