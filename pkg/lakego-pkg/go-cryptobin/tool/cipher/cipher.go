package cipher

import (
    "fmt"
    "errors"
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

// default ciphers
var defaultCiphers = CipherMap{
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

type (
    // CipherFunc
    CipherFunc = func([]byte) (cipher.Block, error)

    // Cipher map
    CipherMap = map[string]CipherFunc
)

var defaultCipher = New()

// return default cipher
func Default() *Cipher {
    return defaultCipher
}

/**
 * Cipher
 *
 * @create 2022-7-26
 * @author deatil
 */
type Cipher struct {
    // ciphers
    ciphers CipherMap
}

// New return a *Cipher
func New() *Cipher {
    cipher := &Cipher{
        ciphers: defaultCiphers,
    }

    return cipher
}

// set ciphers
func (this *Cipher) With(ciphers CipherMap) *Cipher {
    this.ciphers = ciphers

    return this
}

func WithCiphers(ciphers CipherMap) *Cipher {
    return defaultCipher.With(ciphers)
}

// add one Cipher
func (this *Cipher) Add(name string, block CipherFunc) *Cipher {
    this.ciphers[name] = block

    return this
}

func AddCipher(name string, block CipherFunc) *Cipher {
    return defaultCipher.Add(name, block)
}

// get one Cipher
func (this *Cipher) Get(name string) (CipherFunc, error) {
    if cip, ok := this.ciphers[name]; ok {
        return cip, nil
    }

    err := errors.New(fmt.Sprintf("go-cryptobin/tool/cipher: cipher %s not support", name))
    return nil, err
}

func GetCipher(name string) (CipherFunc, error) {
    return defaultCipher.Get(name)
}
