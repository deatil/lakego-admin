package ssh

import (
    "io"
    "fmt"
    "crypto"
)

// 加密接口
// Cipher interface
type Cipher interface {
    // 名称
    // Name
    Name() string

    // 值大小
    // KeySize
    KeySize() int

    // 块大小
    // BlockSize
    BlockSize() int

    // 加密, 返回: [加密后数据, error]
    // Encrypt, return [Encrypted, error]
    Encrypt(key, plaintext []byte) ([]byte, error)

    // 解密
    // Decrypt
    Decrypt(key, ciphertext []byte) ([]byte, error)
}

// KDF 设置接口
// KDF Options
type KDFOpts interface {
    // 名称
    // Name
    Name() string

    // 生成密钥
    // DeriveKey func
    DeriveKey(random io.Reader, password []byte, size int) (key []byte, params string, err error)

    // 随机数大小
    // Get SaltSize
    GetSaltSize() int
}

// 数据接口
// KDF Parameters
type KDFParameters interface {
    // 生成密钥
    // DeriveKey func
    DeriveKey(password []byte, kdfOpts string, size int) (key []byte, err error)
}

// Key 接口
// Key interface
type Key interface {
    // 包装
    // Marshal
    Marshal(key crypto.PrivateKey, comment string) (string, []byte, []byte, error)

    // 解析
    // Parse
    Parse(data []byte) (crypto.PrivateKey, string, error)
}

var ciphers = make(map[string]func() Cipher)

// 添加加密
// add Cipher
func AddCipher(name string, cipher func() Cipher) {
    ciphers[name] = cipher
}

func ParseCipher(cipherName string) (Cipher, error) {
    newCipher, ok := ciphers[cipherName]
    if !ok {
        return nil, fmt.Errorf("ssh: unsupported cipher (%s)", cipherName)
    }

    return newCipher(), nil
}

var kdfs = make(map[string]func() KDFParameters)

// 添加 kdf 方式
// Add KDF
func AddKDF(name string, params func() KDFParameters) {
    kdfs[name] = params
}

// Parse PBKDF
func ParsePBKDF(kdfName string) (KDFParameters, error) {
    newKDF, ok := kdfs[kdfName]
    if !ok {
        return nil, fmt.Errorf("ssh: unsupported kdf (%s)", kdfName)
    }

    return newKDF(), nil
}

var keys = make(map[string]func() Key)

// 添加 Key
// Add Key
func AddKey(name string, key func() Key) {
    keys[name] = key
}

func ParseKeyType(keyName string) (Key, error) {
    newKeyType, ok := keys[keyName]
    if !ok {
        return nil, fmt.Errorf("ssh: unsupported key type %s", keyName)
    }

    return newKeyType(), nil
}

