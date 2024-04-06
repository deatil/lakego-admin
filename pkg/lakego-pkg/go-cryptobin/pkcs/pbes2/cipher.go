package pbes2

import(
    "io"
    "fmt"
    "sync"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/tool"
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
    NeedPasswordBmpString() bool

    // 加密, 返回: [加密后数据, 参数, error]
    Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error)

    // 解密
    Decrypt(key, params, ciphertext []byte) ([]byte, error)
}

// ===============

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

// 获取国密加密
func (this *Ciphers) GetGmSMCipher(oid string, length int) (Cipher, error) {
    if oid == oidSM4.String() {
        if length > 0 {
            oid = oidSM4CBC.String()
        } else {
            oid = oidSM4ECB.String()
        }
    }

    return this.GetCipher(oid)
}

// 获取加密
func GetGmSMCipher(oid string, length int) (Cipher, error) {
    return defaultCiphers.GetGmSMCipher(oid, length)
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

var newPadding = tool.NewPadding()

// 明文补码算法
func pkcs7Padding(text []byte, blockSize int) []byte {
    return newPadding.PKCS7Padding(text, blockSize)
}

// 明文减码算法
func pkcs7UnPadding(src []byte) ([]byte, error) {
    return newPadding.PKCS7UnPadding(src)
}
