package pbes1

import(
    "io"
    "fmt"
    "hash"
    "sync"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/padding"
)

// 密码迭代生成
type DerivedKeyFunc = func(password string, salt string, iter int, keyLen int, ivLen int, h func() hash.Hash) ([]byte, []byte)

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

// ===========

// 默认
var defaultCiphers = NewCiphers()

// 方法
type CipherFunc = func() Cipher

// Ciphers
type Ciphers struct {
    // 锁定
    mu sync.RWMutex

    ciphers map[string]CipherFunc
}

func NewCiphers() *Ciphers {
    return &Ciphers {
        ciphers: make(map[string]CipherFunc),
    }
}

// 添加加密
func (this *Ciphers) AddCipher(oid asn1.ObjectIdentifier, cipher CipherFunc) {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.ciphers[oid.String()] = cipher
}

// 添加加密
func AddCipher(oid asn1.ObjectIdentifier, cipher CipherFunc) {
    defaultCiphers.AddCipher(oid, cipher)
}

// 获取加密
func (this *Ciphers) GetCipher(oid string) (Cipher, error) {
    this.mu.RLock()
    defer this.mu.RUnlock()

    cipher, ok := this.ciphers[oid]
    if !ok {
        return nil, fmt.Errorf("pkcs/cipher: unsupported cipher (OID: %s)", oid)
    }

    newCipher := cipher()

    return newCipher, nil
}

// 获取加密
func GetCipher(oid string) (Cipher, error) {
    return defaultCiphers.GetCipher(oid)
}

// 全部
func (this *Ciphers) All() map[string]CipherFunc {
    this.mu.RLock()
    defer this.mu.RUnlock()

    return this.ciphers
}

// 全部
func AllCipher() map[string]CipherFunc {
    return defaultCiphers.All()
}

// 克隆
func (this *Ciphers) Clone() *Ciphers {
    return &Ciphers {
        ciphers: this.ciphers,
    }
}

// 克隆
func CloneCiphers() *Ciphers {
    return defaultCiphers.Clone()
}

// ===============

var newPadding = padding.NewPKCS7()

// 明文补码算法
func pkcs7Padding(text []byte, blockSize int) []byte {
    return newPadding.Padding(text, blockSize)
}

// 明文减码算法
func pkcs7UnPadding(src []byte) ([]byte, error) {
    return newPadding.UnPadding(src)
}
