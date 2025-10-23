package pkcs

import(
    "io"
    "errors"
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

// 泛型适配对称加密
// T 为对应参数结构
type Sym[T any] struct {
    cipher Cipher
}

func NewSym[T any](cipher Cipher) *Sym[T] {
    return &Sym[T]{
        cipher,
    }
}

// oid
func (this *Sym[T]) OID() asn1.ObjectIdentifier {
    if this.cipher == nil {
        return asn1.ObjectIdentifier{}
    }

    return this.cipher.OID()
}

// 加密
func (this *Sym[T]) Encrypt(rand io.Reader, key, plaintext []byte) (encrypted []byte, params T, err error) {
    if this.cipher == nil {
        err = errors.New("go-cryptobin/pkcs: invalid cipher")
        return
    }

    var paramBytes []byte

    encrypted, paramBytes, err = this.cipher.Encrypt(rand, key, plaintext)
    if err != nil {
        return
    }

    _, err = asn1.Unmarshal(paramBytes, &params)
    if err != nil {
        return
    }

    return encrypted, params, nil
}

// 解密
func (this *Sym[T]) Decrypt(key []byte, params T, ciphertext []byte) ([]byte, error) {
    if this.cipher == nil {
        return nil, errors.New("go-cryptobin/pkcs: invalid cipher")
    }

    paramBytes, err := asn1.Marshal(params)
    if err != nil {
        return nil, err
    }

    return this.cipher.Decrypt(key, paramBytes, ciphertext)
}
