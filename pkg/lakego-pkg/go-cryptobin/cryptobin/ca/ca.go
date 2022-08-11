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
    privateKey any

    // 公钥
    publicKey any

    // [私钥/公钥/cert]数据
    keyData []byte

    // 错误
    Errors []error
}
