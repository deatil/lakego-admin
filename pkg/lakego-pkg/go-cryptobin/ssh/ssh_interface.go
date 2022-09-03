package ssh

import (
    "crypto"
)

// 加密接口
type Cipher interface {
    // 名称
    Name() string

    // 值大小
    KeySize() int

    // 块大小
    BlockSize() int

    // 加密, 返回: [加密后数据, error]
    Encrypt(key, plaintext []byte) ([]byte, error)

    // 解密
    Decrypt(key, ciphertext []byte) ([]byte, error)
}

// KDF 设置接口
type KDFOpts interface {
    // 名称
    Name() string

    // 生成密钥
    DeriveKey(password []byte, size int) (key []byte, params string, err error)

    // 随机数大小
    GetSaltSize() int
}

// 数据接口
type KDFParameters interface {
    // 生成密钥
    DeriveKey(password []byte, kdfOpts string, size int) (key []byte, err error)
}

// Key 接口
type Key interface {
    // 包装
    Marshal(key crypto.PrivateKey, comment string) (string, []byte, []byte, error)

    // 解析
    Parse(data []byte) (crypto.PrivateKey, string, error)
}

var ciphers = make(map[string]func() Cipher)

// 添加加密
func AddCipher(name string, cipher func() Cipher) {
    ciphers[name] = cipher
}

var kdfs = make(map[string]func() KDFParameters)

// 添加 kdf 方式
func AddKDF(name string, params func() KDFParameters) {
    kdfs[name] = params
}

var keys = make(map[string]func() Key)

// 添加Key
func AddKey(name string, key func() Key) {
    keys[name] = key
}

