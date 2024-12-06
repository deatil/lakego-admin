package cipher

import (
    "crypto/aes"
    "crypto/des"
    "crypto/cipher"

    "golang.org/x/crypto/tea"
    "golang.org/x/crypto/xtea"
    "golang.org/x/crypto/cast5"
    "golang.org/x/crypto/twofish"
    "golang.org/x/crypto/blowfish"

    "github.com/deatil/go-cryptobin/cipher/sm4"
)

type (
    // CipherFunc
    CipherFunc = func([]byte) (cipher.Block, error)

    // CipherFunc map 列表
    CipherFuncMap = map[string]CipherFunc
)

var (
    newXteaCipher = func(key []byte) (cipher.Block, error) {
        return xtea.NewCipher(key)
    }
    newTwofishCipher = func(key []byte) (cipher.Block, error) {
        return twofish.NewCipher(key)
    }
    newBlowfishCipher = func(key []byte) (cipher.Block, error) {
        return blowfish.NewCipher(key)
    }
    newCast5Cipher = func(key []byte) (cipher.Block, error) {
        return cast5.NewCipher(key)
    }
)

// 默认列表
var defaultCipherFuncs = CipherFuncMap{
    "Aes":       aes.NewCipher,
    "Des":       des.NewCipher,
    "TripleDes": des.NewTripleDESCipher,
    "Tea":       tea.NewCipher,
    "Xtea":      newXteaCipher,
    "Twofish":   newTwofishCipher,
    "Blowfish":  newBlowfishCipher,
    "Cast5":     newCast5Cipher,
    "SM4":       sm4.NewCipher,
}

var defaultCipher = New()

// return default cipher
func Default() *Cipher {
    return defaultCipher
}

/**
 * 加密方式
 *
 * @create 2022-7-26
 * @author deatil
 */
type Cipher struct {
    // 列表
    funcs CipherFuncMap
}

// 构造函数
func New() *Cipher {
    cipher := &Cipher{
        funcs: defaultCipherFuncs,
    }

    return cipher
}

// 覆盖
func (this *Cipher) WithFunc(funcs CipherFuncMap) *Cipher {
    this.funcs = funcs

    return this
}

func WithFunc(funcs CipherFuncMap) *Cipher {
    return defaultCipher.WithFunc(funcs)
}

// 添加
func (this *Cipher) AddFunc(name string, block CipherFunc) *Cipher {
    this.funcs[name] = block

    return this
}

func AddFunc(name string, block CipherFunc) *Cipher {
    return defaultCipher.AddFunc(name, block)
}

// 类型
func (this *Cipher) GetFunc(name string) CipherFunc {
    if fn, ok := this.funcs[name]; ok {
        return fn
    }

    return this.funcs["Aes"]
}

func GetFunc(name string) CipherFunc {
    return defaultCipher.GetFunc(name)
}
