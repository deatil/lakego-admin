package pkcs1

import(
    "io"
    "fmt"
    "crypto/md5"

    "github.com/deatil/go-cryptobin/padding"
)

// 加密接口
type Cipher interface {
    // 名称
    Name() string

    // 块大小
    BlockSize() int

    // 加密, 返回: [加密后数据, iv, error]
    Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error)

    // 解密
    Decrypt(key, iv, ciphertext []byte) ([]byte, error)
}

var ciphers = make(map[string]func() Cipher)

// 添加加密
func AddCipher(name string, cipher func() Cipher) {
    ciphers[name] = cipher
}

// 获取加密
func GetCipher(name string) (Cipher, error) {
    cipher, ok := ciphers[name]
    if !ok {
        return nil, fmt.Errorf("go-cryptobin/pkcs1: unsupported cipher %s", name)
    }

    newCipher := cipher()

    return newCipher, nil
}

// ===============

// 密钥生成器
func DeriveKey(password, salt []byte, keySize int) []byte {
    hash := md5.New()
    out := make([]byte, keySize)
    var digest []byte

    for i := 0; i < len(out); i += len(digest) {
        hash.Reset()
        hash.Write(digest)
        hash.Write(password)
        hash.Write(salt)
        digest = hash.Sum(digest[:0])
        copy(out[i:], digest)
    }

    return out
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
