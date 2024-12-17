package crypto

import (
    "fmt"
    "errors"
    "crypto/md5"
    "crypto/aes"
    "crypto/des"
    "crypto/rc4"
    "crypto/cipher"

    "golang.org/x/crypto/xts"
    "golang.org/x/crypto/tea"
    "golang.org/x/crypto/xtea"
    "golang.org/x/crypto/cast5"
    "golang.org/x/crypto/twofish"
    "golang.org/x/crypto/blowfish"
    "golang.org/x/crypto/chacha20"
    "golang.org/x/crypto/chacha20poly1305"

    "github.com/deatil/go-cryptobin/cipher/sm4"
    "github.com/deatil/go-cryptobin/cipher/rc2"
    "github.com/deatil/go-cryptobin/cipher/rc5"
    "github.com/deatil/go-cryptobin/cipher/rc6"
    "github.com/deatil/go-cryptobin/cipher/idea"
    "github.com/deatil/go-cryptobin/cipher/seed"
    "github.com/deatil/go-cryptobin/cipher/aria"
    "github.com/deatil/go-cryptobin/cipher/camellia"
    "github.com/deatil/go-cryptobin/cipher/gost"
    "github.com/deatil/go-cryptobin/cipher/kuznyechik"
    "github.com/deatil/go-cryptobin/cipher/serpent"
    "github.com/deatil/go-cryptobin/cipher/saferplus"
    "github.com/deatil/go-cryptobin/cipher/hight"
    "github.com/deatil/go-cryptobin/cipher/lea"
    "github.com/deatil/go-cryptobin/cipher/kasumi"
    "github.com/deatil/go-cryptobin/cipher/safer"
    "github.com/deatil/go-cryptobin/cipher/multi2"
    "github.com/deatil/go-cryptobin/cipher/kseed"
    "github.com/deatil/go-cryptobin/cipher/khazad"
    "github.com/deatil/go-cryptobin/cipher/present"
    "github.com/deatil/go-cryptobin/cipher/trivium"
    "github.com/deatil/go-cryptobin/cipher/rijndael"
    "github.com/deatil/go-cryptobin/cipher/twine"
    "github.com/deatil/go-cryptobin/cipher/misty1"
    cryptobin_des "github.com/deatil/go-cryptobin/cipher/des"
    tool_cipher "github.com/deatil/go-cryptobin/tool/cipher"
)

// 获取模式方式
// get mode type
func getMode(opt IOption) (IMode, error) {
    mode := opt.Mode()
    if !UseMode.Has(mode) {
        err := errors.New(fmt.Sprintf("the mode %s is not exists.", mode))
        return nil, err
    }

    // 模式
    newMode := UseMode.Get(mode)

    return newMode(), nil
}

// 获取补码方式
// get padding type
func getPadding(opt IOption) (IPadding, error) {
    padding := opt.Padding()
    if !UsePadding.Has(padding) {
        err := errors.New(fmt.Sprintf("the padding %s is not exists.", padding))
        return nil, err
    }

    // 补码数据
    newPadding := UsePadding.Get(padding)

    return newPadding(), nil
}

// 块加密
// Block Encrypt
func BlockEncrypt(block cipher.Block, data []byte, opt IOption) ([]byte, error) {
    bs := block.BlockSize()

    // 补码
    newPadding, err := getPadding(opt)
    if err != nil {
        return nil, err
    }

    plainPadding := newPadding.Padding(data, bs, opt)

    // 补码后需要验证 / check padding
    if opt.Padding() != NoPadding {
        if len(plainPadding)%bs != 0 {
            err := errors.New(fmt.Sprintf("the length of the completed data must be an integer multiple of the block, the completed data size is %d, block size is %d", len(plainPadding), bs))
            return nil, err
        }
    }

    // 模式 / mode
    newMode, err := getMode(opt)
    if err != nil {
        return nil, err
    }

    return newMode.Encrypt(plainPadding, block, opt)
}

// 块解密
// Block Decrypt
func BlockDecrypt(block cipher.Block, data []byte, opt IOption) ([]byte, error) {
    bs := block.BlockSize()

    // 补码后需要验证 / check padding
    if opt.Padding() != NoPadding {
        if len(data)%bs != 0 {
            err := errors.New(fmt.Sprintf("improper decrypt type, block size is %d", bs))
            return nil, err
        }
    }

    // 模式
    newMode, err := getMode(opt)
    if err != nil {
        return nil, err
    }

    dst, err := newMode.Decrypt(data, block, opt)
    if err != nil {
        return nil, err
    }

    // 补码
    newPadding, err := getPadding(opt)
    if err != nil {
        return nil, err
    }

    // 去除补码数据
    dst, err = newPadding.UnPadding(dst, opt)
    if err != nil {
        return nil, err
    }

    return dst, nil
}

// ===================

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
type EncryptAes struct {}

// 加密 / Encrypt
func (this EncryptAes) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := aes.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptAes) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := aes.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptDes struct {}

// 加密 / Encrypt
func (this EncryptDes) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := des.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptDes) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := des.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptTwoDes struct {}

// 加密 / Encrypt
func (this EncryptTwoDes) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := cryptobin_des.NewTwoDESCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptTwoDes) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := cryptobin_des.NewTwoDESCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptTripleDes struct {}

// 加密 / Encrypt
func (this EncryptTripleDes) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := des.NewTripleDESCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptTripleDes) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := des.NewTripleDESCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

// The key argument should be the Twofish key,
// 16, 24 or 32 bytes.
type EncryptTwofish struct {}

// 加密 / Encrypt
func (this EncryptTwofish) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := twofish.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptTwofish) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := twofish.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptBlowfish struct {}

// 加密 / Encrypt
func (this EncryptBlowfish) getBlock(opt IOption) (cipher.Block, error) {
    if opt.Config().Has("salt") {
        return blowfish.NewSaltedCipher(opt.Key(), opt.Config().GetBytes("salt"))
    }

    return blowfish.NewCipher(opt.Key())
}

// 加密 / Encrypt
func (this EncryptBlowfish) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptBlowfish) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptTea struct {}

// 加密 / Encrypt
func (this EncryptTea) getBlock(opt IOption) (cipher.Block, error) {
    // key is 16 bytes
    if opt.Config().Has("rounds") {
        return tea.NewCipherWithRounds(opt.Key(), opt.Config().GetInt("rounds"))
    }

    return tea.NewCipher(opt.Key())
}

// 加密 / Encrypt
func (this EncryptTea) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptTea) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptXtea struct {}

// 加密 / Encrypt
func (this EncryptXtea) getBlock(opt IOption) (cipher.Block, error) {
    // XTEA only supports 128 bit (16 byte) keys.
    return xtea.NewCipher(opt.Key())
}

// 加密 / Encrypt
func (this EncryptXtea) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptXtea) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptCast5 struct {}

// 加密 / Encrypt
func (this EncryptCast5) getBlock(opt IOption) (cipher.Block, error) {
    // Cast5 only supports 128 bit (16 byte) keys.
    return cast5.NewCipher(opt.Key())
}

// 加密 / Encrypt
func (this EncryptCast5) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptCast5) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptRC2 struct {}

// 加密 / Encrypt
func (this EncryptRC2) getBlock(opt IOption) (cipher.Block, error) {
    // RC2 key, at least 1 byte and at most 128 bytes.
    key := opt.Key()

    return rc2.NewCipher(key, len(key)*8)
}

// 加密 / Encrypt
func (this EncryptRC2) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptRC2) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptRC5 struct {}

// 加密 / Encrypt
func (this EncryptRC5) getBlock(opt IOption) (cipher.Block, error) {
    // wordSize is 16, 32 or 64
    wordSize := uint(32)
    if opt.Config().Has("word_size") {
        wordSize = opt.Config().GetUint("word_size")
    }

    // rounds at least 8 byte and at most 127 bytes.
    rounds := uint(64)
    if opt.Config().Has("rounds") {
        rounds = opt.Config().GetUint("rounds")
    }

    key := opt.Key()

    // RC5 key is 16, 24 or 32 bytes.
    return rc5.NewCipher(key, wordSize, rounds)
}

// 加密 / Encrypt
func (this EncryptRC5) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptRC5) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptRC6 struct {}

// 加密 / Encrypt
func (this EncryptRC6) Encrypt(data []byte, opt IOption) ([]byte, error) {
    // RC6 key is 16 bytes.
    block, err := rc6.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptRC6) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := rc6.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptIdea struct {}

// 加密 / Encrypt
func (this EncryptIdea) getBlock(opt IOption) (cipher.Block, error) {
    // Idea only supports 128 bit (16 byte) keys.
    return idea.NewCipher(opt.Key())
}

// 加密 / Encrypt
func (this EncryptIdea) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptIdea) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptSM4 struct {}

// 加密 / Encrypt
func (this EncryptSM4) getBlock(opt IOption) (cipher.Block, error) {
    // 国密 sm4 加密
    return sm4.NewCipher(opt.Key())
}

// 加密 / Encrypt
func (this EncryptSM4) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptSM4) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

// 32 bytes key and a 12 or 24 bytes nonce(iv)
type EncryptChacha20 struct {}

// 加密 / Encrypt
func (this EncryptChacha20) Encrypt(data []byte, opt IOption) ([]byte, error) {
    iv := opt.Iv()

    chacha, err := chacha20.NewUnauthenticatedCipher(opt.Key(), iv)
    if err != nil {
        return nil, err
    }

    if opt.Config().Has("counter") {
        chacha.SetCounter(opt.Config().GetUint32("counter"))
    }

    dst := make([]byte, len(data))

    chacha.XORKeyStream(dst, data)

    return dst, nil
}

// 解密 / Decrypt
func (this EncryptChacha20) Decrypt(data []byte, opt IOption) ([]byte, error) {
    iv := opt.Iv()

    chacha, err := chacha20.NewUnauthenticatedCipher(opt.Key(), iv)
    if err != nil {
        return nil, err
    }

    if opt.Config().Has("counter") {
        chacha.SetCounter(opt.Config().GetUint32("counter"))
    }

    dst := make([]byte, len(data))

    chacha.XORKeyStream(dst, data)

    return dst, nil
}

// ===================

// 32 bytes key
type EncryptChacha20poly1305 struct {}

// 加密 / Encrypt
func (this EncryptChacha20poly1305) Encrypt(data []byte, opt IOption) ([]byte, error) {
    aead, err := chacha20poly1305.New(opt.Key())
    if err != nil {
        return nil, err
    }

    iv := opt.Iv()
    if len(iv) == 0 {
        err := fmt.Errorf("iv empty.")
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")

    dst := aead.Seal(nil, iv, data, additional)

    return dst, nil
}

// 解密 / Decrypt
func (this EncryptChacha20poly1305) Decrypt(data []byte, opt IOption) ([]byte, error) {
    chacha, err := chacha20poly1305.New(opt.Key())
    if err != nil {
        return nil, err
    }

    iv := opt.Iv()
    if len(iv) == 0 {
        err := fmt.Errorf("iv empty.")
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")

    return chacha.Open(nil, iv, data, additional)
}

// ===================

// 32 bytes key
type EncryptChacha20poly1305X struct {}

// 加密 / Encrypt
func (this EncryptChacha20poly1305X) Encrypt(data []byte, opt IOption) ([]byte, error) {
    aead, err := chacha20poly1305.NewX(opt.Key())
    if err != nil {
        return nil, err
    }

    iv := opt.Iv()
    if len(iv) == 0 {
        err := fmt.Errorf("iv empty.")
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")

    dst := aead.Seal(nil, iv, data, additional)

    return dst, nil
}

// 解密 / Decrypt
func (this EncryptChacha20poly1305X) Decrypt(data []byte, opt IOption) ([]byte, error) {
    chacha, err := chacha20poly1305.NewX(opt.Key())
    if err != nil {
        return nil, err
    }

    iv := opt.Iv()
    if len(iv) == 0 {
        err := fmt.Errorf("iv empty.")
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")

    return chacha.Open(nil, iv, data, additional)
}

// ===================

// RC4 key, at least 1 byte and at most 256 bytes.
type EncryptRC4 struct {}

// 加密 / Encrypt
func (this EncryptRC4) Encrypt(data []byte, opt IOption) ([]byte, error) {
    rc, err := rc4.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))

    rc.XORKeyStream(dst, data)

    return dst, nil
}

// 解密 / Decrypt
func (this EncryptRC4) Decrypt(data []byte, opt IOption) ([]byte, error) {
    rc, err := rc4.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))

    rc.XORKeyStream(dst, data)

    return dst, nil
}

// ===================

// RC4 key, at least 1 byte and at most 256 bytes.
type EncryptRC4MD5 struct {}

// 加密 / Encrypt
func (this EncryptRC4MD5) getCipher(opt IOption) (cipher.Stream, error) {
    h := md5.New()
    h.Write(opt.Key())
    h.Write(opt.Iv())

    return rc4.NewCipher(h.Sum(nil))
}

// 加密 / Encrypt
func (this EncryptRC4MD5) Encrypt(data []byte, opt IOption) ([]byte, error) {
    rc, err := this.getCipher(opt)
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))

    rc.XORKeyStream(dst, data)

    return dst, nil
}

// 解密 / Decrypt
func (this EncryptRC4MD5) Decrypt(data []byte, opt IOption) ([]byte, error) {
    rc, err := this.getCipher(opt)
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))

    rc.XORKeyStream(dst, data)

    return dst, nil
}

// ===================

// Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
type EncryptXts struct {}

// 加密 / Encrypt
func (this EncryptXts) Encrypt(data []byte, opt IOption) ([]byte, error) {
    if !opt.Config().Has("cipher") {
        err := fmt.Errorf("cipher is empty.")
        return nil, err
    }

    if !opt.Config().Has("sector_num") {
        err := fmt.Errorf("sector_num is empty.")
        return nil, err
    }

    cipher := opt.Config().GetString("cipher")
    sectorNum := opt.Config().GetUint64("sector_num")

    cip, err := tool_cipher.GetCipher(cipher)
    if err != nil {
        return nil, err
    }

    xc, err := xts.NewCipher(cip, opt.Key())
    if err != nil {
        return nil, err
    }

    // 大小
    bs := 16

    // 补码
    newPadding, err := getPadding(opt)
    if err != nil {
        return nil, err
    }

    // 补码数据
    plainPadding := newPadding.Padding(data, bs, opt)

    dst := make([]byte, len(plainPadding))

    xc.Encrypt(dst, plainPadding, sectorNum)

    return dst, nil
}

// 解密 / Decrypt
func (this EncryptXts) Decrypt(data []byte, opt IOption) ([]byte, error) {
    if !opt.Config().Has("cipher") {
        err := fmt.Errorf("cipher is empty.")
        return nil, err
    }

    if !opt.Config().Has("sector_num") {
        err := fmt.Errorf("sector_num is empty.")
        return nil, err
    }

    cipher := opt.Config().GetString("cipher")
    sectorNum := opt.Config().GetUint64("sector_num")

    cip, err := tool_cipher.GetCipher(cipher)
    if err != nil {
        return nil, err
    }

    xc, err := xts.NewCipher(cip, opt.Key())
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))

    xc.Decrypt(dst, data, sectorNum)

    // 补码
    newPadding, err := getPadding(opt)
    if err != nil {
        return nil, err
    }

    // 解码数据
    dst, err = newPadding.UnPadding(dst, opt)
    if err != nil {
        return nil, err
    }

    return dst, nil
}

// ===================

// Seed key is 16 bytes.
type EncryptSeed struct {}

// 加密 / Encrypt
func (this EncryptSeed) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := seed.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptSeed) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := seed.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

// Aria key is 16, 24, or 32 bytes.
type EncryptAria struct {}

// 加密 / Encrypt
func (this EncryptAria) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := aria.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptAria) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := aria.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

// Camellia key is 16, 24, or 32 bytes.
type EncryptCamellia struct {}

// 加密 / Encrypt
func (this EncryptCamellia) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := camellia.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptCamellia) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := camellia.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

// Gost key is 32 bytes.
type EncryptGost struct {}

// 加密 / Encrypt
func (this EncryptGost) getCipher(opt IOption) (cipher.Block, error) {
    s := opt.Config().Get("sbox")

    var sbox [][]byte

    switch v := s.(type) {
        case [][]byte:
            sbox = v
        case string:
            switch v {
                case "SboxDESDerivedParamSet":
                    sbox = gost.SboxDESDerivedParamSet
                case "SboxRFC4357TestParamSet":
                    sbox = gost.SboxRFC4357TestParamSet
                case "SboxGostR341194CryptoProParamSet":
                    sbox = gost.SboxGostR341194CryptoProParamSet
                case "SboxTC26gost28147paramZ":
                    sbox = gost.SboxTC26gost28147paramZ
                case "SboxEACParamSet":
                    sbox = gost.SboxEACParamSet
            }
    }

    if sbox == nil {
        err := fmt.Errorf("sbox is error")
        return nil, err
    }

    block, err := gost.NewCipher(opt.Key(), sbox)
    if err != nil {
        return nil, err
    }

    return block, nil
}

// 加密 / Encrypt
func (this EncryptGost) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getCipher(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptGost) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getCipher(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

// Kuznyechik key is 32 bytes.
type EncryptKuznyechik struct {}

// 加密 / Encrypt
func (this EncryptKuznyechik) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := kuznyechik.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptKuznyechik) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := kuznyechik.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

// Serpent key is 16, 24, 32 bytes.
type EncryptSerpent struct {}

// 加密 / Encrypt
func (this EncryptSerpent) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := serpent.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptSerpent) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := serpent.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

func init() {
    UseEncrypt.Add(Aes, func() IEncrypt {
        return EncryptAes{}
    })
    UseEncrypt.Add(Des, func() IEncrypt {
        return EncryptDes{}
    })
    UseEncrypt.Add(TwoDes, func() IEncrypt {
        return EncryptTwoDes{}
    })
    UseEncrypt.Add(TripleDes, func() IEncrypt {
        return EncryptTripleDes{}
    })
    UseEncrypt.Add(Twofish, func() IEncrypt {
        return EncryptTwofish{}
    })
    UseEncrypt.Add(Blowfish, func() IEncrypt {
        return EncryptBlowfish{}
    })
    UseEncrypt.Add(Tea, func() IEncrypt {
        return EncryptTea{}
    })
    UseEncrypt.Add(Xtea, func() IEncrypt {
        return EncryptXtea{}
    })
    UseEncrypt.Add(Cast5, func() IEncrypt {
        return EncryptCast5{}
    })
    UseEncrypt.Add(RC2, func() IEncrypt {
        return EncryptRC2{}
    })
    UseEncrypt.Add(RC4, func() IEncrypt {
        return EncryptRC4{}
    })
    UseEncrypt.Add(RC4MD5, func() IEncrypt {
        return EncryptRC4MD5{}
    })
    UseEncrypt.Add(RC5, func() IEncrypt {
        return EncryptRC5{}
    })
    UseEncrypt.Add(RC6, func() IEncrypt {
        return EncryptRC6{}
    })
    UseEncrypt.Add(SM4, func() IEncrypt {
        return EncryptSM4{}
    })
    UseEncrypt.Add(Idea, func() IEncrypt {
        return EncryptIdea{}
    })
    UseEncrypt.Add(Chacha20, func() IEncrypt {
        return EncryptChacha20{}
    })
    UseEncrypt.Add(Chacha20poly1305, func() IEncrypt {
        return EncryptChacha20poly1305{}
    })
    UseEncrypt.Add(Chacha20poly1305X, func() IEncrypt {
        return EncryptChacha20poly1305X{}
    })
    UseEncrypt.Add(Xts, func() IEncrypt {
        return EncryptXts{}
    })
    UseEncrypt.Add(Seed, func() IEncrypt {
        return EncryptSeed{}
    })
    UseEncrypt.Add(Aria, func() IEncrypt {
        return EncryptAria{}
    })
    UseEncrypt.Add(Camellia, func() IEncrypt {
        return EncryptCamellia{}
    })
    UseEncrypt.Add(Gost, func() IEncrypt {
        return EncryptGost{}
    })
    UseEncrypt.Add(Kuznyechik, func() IEncrypt {
        return EncryptKuznyechik{}
    })
    UseEncrypt.Add(Serpent, func() IEncrypt {
        return EncryptSerpent{}
    })
}

// ===================

// Saferplus key is 8, 16 bytes.
type EncryptSaferplus struct {}

// 加密 / Encrypt
func (this EncryptSaferplus) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := saferplus.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptSaferplus) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := saferplus.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Saferplus, func() IEncrypt {
        return EncryptSaferplus{}
    })
}

// ===================

// The key argument should be 16 bytes.
type EncryptHight struct {}

// 加密 / Encrypt
func (this EncryptHight) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := hight.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptHight) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := hight.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Hight, func() IEncrypt {
        return EncryptHight{}
    })
}

// ===================

// The key argument should be 16, 24, 32 bytes.
type EncryptLea struct {}

// 加密 / Encrypt
func (this EncryptLea) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := lea.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptLea) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := lea.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Lea, func() IEncrypt {
        return EncryptLea{}
    })
}

// ===================

// The key argument should be 16 bytes.
type EncryptKasumi struct {}

// 加密 / Encrypt
func (this EncryptKasumi) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := kasumi.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptKasumi) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := kasumi.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Kasumi, func() IEncrypt {
        return EncryptKasumi{}
    })
}

// ===================

// The key argument should be 16, 24, 32 bytes.
type EncryptSafer struct {}

// 加密 / Encrypt
func (this EncryptSafer) getBlock(opt IOption) (cipher.Block, error) {
    typ := opt.Config().GetString("type")
    rounds := opt.Config().GetInt32("rounds")

    if typ == "SK" {
        return safer.NewSKCipher(opt.Key(), rounds)
    }

    return safer.NewKCipher(opt.Key(), rounds)
}

// 加密 / Encrypt
func (this EncryptSafer) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptSafer) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Safer, func() IEncrypt {
        return EncryptSafer{}
    })
}

// ===================

// The key argument should be 40 bytes.
type EncryptMulti2 struct {}

// 加密 / Encrypt
func (this EncryptMulti2) Encrypt(data []byte, opt IOption) ([]byte, error) {
    rounds := opt.Config().GetInt32("rounds")

    block, err := multi2.NewCipher(opt.Key(), rounds)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptMulti2) Decrypt(data []byte, opt IOption) ([]byte, error) {
    rounds := opt.Config().GetInt32("rounds")

    block, err := multi2.NewCipher(opt.Key(), rounds)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Multi2, func() IEncrypt {
        return EncryptMulti2{}
    })
}

// ===================

// The key argument should be 16 bytes.
type EncryptKseed struct {}

// 加密 / Encrypt
func (this EncryptKseed) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := kseed.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptKseed) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := kseed.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Kseed, func() IEncrypt {
        return EncryptKseed{}
    })
}

// ===================

// The key argument should be 16 bytes.
type EncryptKhazad struct {}

// 加密 / Encrypt
func (this EncryptKhazad) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := khazad.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptKhazad) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := khazad.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Khazad, func() IEncrypt {
        return EncryptKhazad{}
    })
}

// ===================

// The key argument should be 16, 20, 24, 28, 32, 36, and 40 bytes.
type EncryptPresent struct {}

// 加密 / Encrypt
func (this EncryptPresent) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := present.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptPresent) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := present.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Present, func() IEncrypt {
        return EncryptPresent{}
    })
}

// ===================

// The key argument should be 10 bytes.
type EncryptTrivium struct {}

// 加密 / Encrypt
func (this EncryptTrivium) Encrypt(data []byte, opt IOption) ([]byte, error) {
    c, err := trivium.NewCipher(opt.Key(), opt.Iv())
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))

    c.XORKeyStream(dst, data)

    return dst, nil
}

// 解密 / Decrypt
func (this EncryptTrivium) Decrypt(data []byte, opt IOption) ([]byte, error) {
    c, err := trivium.NewCipher(opt.Key(), opt.Iv())
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))

    c.XORKeyStream(dst, data)

    return dst, nil
}

func init() {
    UseEncrypt.Add(Trivium, func() IEncrypt {
        return EncryptTrivium{}
    })
}

// ===================

// The key argument should be 16, 24 or 32 bytes.
type EncryptRijndael struct {}

// 加密 / Encrypt
func (this EncryptRijndael) Encrypt(data []byte, opt IOption) ([]byte, error) {
    blockSize := opt.Config().GetInt("block_size")

    block, err := rijndael.NewCipher(opt.Key(), blockSize)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptRijndael) Decrypt(data []byte, opt IOption) ([]byte, error) {
    blockSize := opt.Config().GetInt("block_size")

    block, err := rijndael.NewCipher(opt.Key(), blockSize)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Rijndael, func() IEncrypt {
        return EncryptRijndael{}
    })
}

// ===================

// The key argument should be 16, 24 or 32 bytes.
type EncryptRijndael128 struct {}

// 加密 / Encrypt
func (this EncryptRijndael128) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := rijndael.NewCipher128(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptRijndael128) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := rijndael.NewCipher128(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Rijndael128, func() IEncrypt {
        return EncryptRijndael128{}
    })
}

// ===================

// The key argument should be 16, 24 or 32 bytes.
type EncryptRijndael192 struct {}

// 加密 / Encrypt
func (this EncryptRijndael192) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := rijndael.NewCipher192(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptRijndael192) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := rijndael.NewCipher192(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Rijndael192, func() IEncrypt {
        return EncryptRijndael192{}
    })
}

// ===================

// The key argument should be 16, 24 or 32 bytes.
type EncryptRijndael256 struct {}

// 加密 / Encrypt
func (this EncryptRijndael256) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := rijndael.NewCipher256(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptRijndael256) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := rijndael.NewCipher256(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Rijndael256, func() IEncrypt {
        return EncryptRijndael256{}
    })
}

// ===================

// The key argument should be 10 or 16 bytes.
type EncryptTwine struct {}

// 加密 / Encrypt
func (this EncryptTwine) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := twine.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptTwine) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := twine.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Twine, func() IEncrypt {
        return EncryptTwine{}
    })
}

// ===================

// The key argument should be 16 bytes.
type EncryptMisty1 struct {}

// 加密 / Encrypt
func (this EncryptMisty1) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := misty1.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptMisty1) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := misty1.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

func init() {
    UseEncrypt.Add(Misty1, func() IEncrypt {
        return EncryptMisty1{}
    })
}
