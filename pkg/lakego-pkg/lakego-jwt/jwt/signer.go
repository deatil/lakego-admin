package jwt

import(
    "sync"
)

// 默认
var defaultSigner = NewSigner()

type (
    // 签名方法
    SignerMethod = func(IConfig) ISigner
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

/**
 * 签名
 */
func NewSigner() *Signer {
    return &Signer{
        signers: make(map[string]SignerMethod),
    }
}

// 注册
func (this *Signer) AddSigner(name string, method SignerMethod) {
    this.mu.Lock()
    defer this.mu.Unlock()

    if _, exists := this.signers[name]; exists {
        delete(this.signers, name)
    }

    this.signers[name] = method
}

// 添加签名
func AddSigner(name string, method SignerMethod) {
    defaultSigner.AddSigner(name, method)
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
    return defaultSigner.GetSigner(name)
}

// 获取全部
func (this *Signer) GetAllSigner() map[string]SignerMethod {
    return this.signers
}

// 获取全部签名
func GetAllSigner() map[string]SignerMethod {
    return defaultSigner.GetAllSigner()
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
    return defaultSigner.HasSigner(name)
}

// 删除
func (this *Signer) DeleteSigner(name string) {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.signers, name)
}

// 判断签名
func DeleteSigner(name string) {
    defaultSigner.DeleteSigner(name)
}
