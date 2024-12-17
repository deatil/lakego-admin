package pkcs12

import (
    "io"
    "sync"
    "errors"
    "crypto"
    "encoding/asn1"
)

// 加密接口
type Cipher interface {
    // oid
    OID() asn1.ObjectIdentifier

    // 值大小
    KeySize() int

    // 是否有 KeyLength
    HasKeyLength() bool

    // 密码是否需要 Bmp 处理
    NeedBmpPassword() bool

    // 加密, 返回: [加密后数据, 参数, error]
    Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error)

    // 解密
    Decrypt(key, params, ciphertext []byte) ([]byte, error)
}

// Key 接口
type Key interface {
    // 包装默认证书
    MarshalPrivateKey(privateKey crypto.PrivateKey) (pkData []byte, err error)

    // 包装 PKCS8 证书
    MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) (pkData []byte, err error)

    // 解析 PKCS8 证书
    ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error)
}

// 数据接口
type MacKDFParameters interface {
    // 验证
    Verify(message []byte, password []byte) (err error)
}

// KDF 设置接口
type MacKDFOpts interface {
    // 构造
    Compute(message []byte, password []byte) (data MacKDFParameters, err error)
}

// =================

// 默认
var defaultKeys = NewKeys()

// 方法
type KeyFunc = func() Key

// Key 数据
type Keys struct {
    // 读写锁
    mu sync.RWMutex

    keys map[string]KeyFunc
}

func NewKeys() *Keys {
    return &Keys {
        keys: make(map[string]KeyFunc),
    }
}

// 添加 Key
func (this *Keys) AddKey(name string, key KeyFunc) {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.keys[name] = key
}

// 添加 Key
func AddKey(name string, key KeyFunc) {
    defaultKeys.AddKey(name, key)
}

// 获取 Key
func (this *Keys) GetKey(name string) (KeyFunc, error) {
    this.mu.RLock()
    defer this.mu.RUnlock()

    key, ok := this.keys[name]
    if !ok {
        return nil, errors.New("go-cryptobin/pkcs12: unsupported key type " + name)
    }

    return key, nil
}

// 获取 Key
func GetKey(name string) (KeyFunc, error) {
    return defaultKeys.GetKey(name)
}

// 全部
func (this *Keys) All() map[string]KeyFunc {
    this.mu.RLock()
    defer this.mu.RUnlock()

    return this.keys
}

// 全部
func AllKey() map[string]KeyFunc {
    return defaultKeys.All()
}

// 克隆
func (this *Keys) Clone() *Keys {
    this.mu.RLock()
    defer this.mu.RUnlock()

    return &Keys {
        keys: this.keys,
    }
}

// 克隆
func CloneKeys() *Keys {
    return defaultKeys.Clone()
}
