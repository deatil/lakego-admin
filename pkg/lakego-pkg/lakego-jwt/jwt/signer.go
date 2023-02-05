package jwt

import(
    "sync"

    "github.com/deatil/lakego-jwt/jwt/signer"
    "github.com/deatil/lakego-jwt/jwt/config"
    "github.com/deatil/lakego-jwt/jwt/interfaces"
)

var instanceSigner *Signer
var onceSigner sync.Once

/**
 * 签名
 */
func NewSigner() *Signer {
    onceSigner.Do(func() {
        instanceSigner = &Signer{
            signers: DefaultSignerList,
        }
    })

    return instanceSigner
}

// 添加签名
func AddSigner(name string, signer SignerMethod) {
    NewSigner().Add(name, signer)
}

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

type (
    // 签名方法
    SignerMethod = func(config.SignerConfig) interfaces.Signer
)

/**
 * 注册器
 *
 * @create 2021-9-6
 * @author deatil
 */
type Signer struct {
    // 锁定
    mu sync.RWMutex

    // 已注册数据
    signers map[string]SignerMethod
}

// 注册
func (this *Signer) Add(name string, signer SignerMethod) {
    this.mu.Lock()
    defer this.mu.Unlock()

    if _, exists := this.signers[name]; exists {
        delete(this.signers, name)
    }

    this.signers[name] = signer
}

// 获取
func (this *Signer) Get(name string) SignerMethod {
    this.mu.RLock()
    defer this.mu.RUnlock()

    signer, exists := this.signers[name]
    if exists {
        return signer
    }

    return nil
}

// 获取全部
func (this *Signer) GetAll() map[string]SignerMethod {
    return this.signers
}

// 判断
func (this *Signer) Exists(name string) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    _, exists := this.signers[name]

    return exists
}

// 删除
func (this *Signer) Delete(name string) {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.signers, name)
}
