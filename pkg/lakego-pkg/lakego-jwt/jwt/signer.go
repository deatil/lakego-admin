package jwt

import(
    "sync"

    "github.com/deatil/lakego-jwt/jwt/signer"
    "github.com/deatil/lakego-jwt/jwt/config"
    "github.com/deatil/lakego-jwt/jwt/interfaces"
)

// 验证方式列表
var DefaultSignerList = map[string]SignerMethod {
    // Hmac
    "HS256": signer.SignerHS256,
    "HS384": signer.SignerHS384,
    "HS512": signer.SignerHS512,

    // RSA
    "RS256": signer.SignerRS256,
    "RS384": signer.SignerRS384,
    "RS512": signer.SignerRS512,

    // PSS
    "PS256": signer.SignerPS256,
    "PS384": signer.SignerPS384,
    "PS512": signer.SignerPS512,

    // ECDSA
    "ES256": signer.SignerES256,
    "ES384": signer.SignerES384,
    "ES512": signer.SignerES512,

    // EdDSA
    "EdDSA": signer.SignerEdDSA,

    // 国密 SM2
    "GmSM2": signer.SignerGmSM2,
}

// 默认
var DefaultSigner *Signer

func init() {
    DefaultSigner = NewSigner()
    DefaultSigner.signers = DefaultSignerList
}

/**
 * 签名
 */
func NewSigner() *Signer {
    return &Signer{
        signers: make(map[string]SignerMethod),
    }
}

type (
    // 签名方法
    SignerMethod = func(config.SignerConfig) interfaces.Signer
)

/**
 * 签名
 *
 * @create 2023-2-5
 * @author deatil
 */
type Signer struct {
    // 锁定
    mu sync.RWMutex

    // 已注册数据
    signers map[string]SignerMethod
}

// 注册
func (this *Signer) AddSigner(name string, signer SignerMethod) {
    this.mu.Lock()
    defer this.mu.Unlock()

    if _, exists := this.signers[name]; exists {
        delete(this.signers, name)
    }

    this.signers[name] = signer
}

// 添加签名
func AddSigner(name string, signer SignerMethod) {
    DefaultSigner.AddSigner(name, signer)
}

// 获取
func (this *Signer) GetSigner(name string) SignerMethod {
    this.mu.RLock()
    defer this.mu.RUnlock()

    signer, exists := this.signers[name]
    if exists {
        return signer
    }

    return nil
}

// 获取签名
func GetSigner(name string) SignerMethod {
    return DefaultSigner.GetSigner(name)
}

// 获取全部
func (this *Signer) GetAllSigner() map[string]SignerMethod {
    return this.signers
}

// 获取全部签名
func GetAllSigner() map[string]SignerMethod {
    return DefaultSigner.GetAllSigner()
}

// 判断
func (this *Signer) HasSigner(name string) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    _, exists := this.signers[name]

    return exists
}

// 判断签名
func HasSigner(name string) bool {
    return DefaultSigner.HasSigner(name)
}

// 删除
func (this *Signer) DeleteSigner(name string) {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.signers, name)
}

// 判断签名
func DeleteSigner(name string) {
    DefaultSigner.DeleteSigner(name)
}
