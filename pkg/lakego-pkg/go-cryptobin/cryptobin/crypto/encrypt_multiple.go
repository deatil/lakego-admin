package crypto

import (
    "fmt"
    "errors"
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

    "github.com/tjfoc/gmsm/sm4"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
    cryptobin_rc2 "github.com/deatil/go-cryptobin/cipher/rc2"
    cryptobin_rc5 "github.com/deatil/go-cryptobin/cipher/rc5"
)

// 获取模式方式
func getMode(opt IOption) (IMode, error) {
    mode := opt.Mode()
    if !UseMode.Has(mode) {
        err := errors.New(fmt.Sprintf("Cryptobin: the mode %s is not exists.", mode))
        return nil, err
    }

    // 模式
    newMode := UseMode.Get(mode)

    return newMode(), nil
}

// 获取补码方式
func getPadding(opt IOption) (IPadding, error) {
    padding := opt.Padding()
    if !UsePadding.Has(padding) {
        err := errors.New(fmt.Sprintf("Cryptobin: the padding %s is not exists.", padding))
        return nil, err
    }

    // 补码数据
    newPadding := UsePadding.Get(padding)

    return newPadding(), nil
}

// 加密
func BlockEncrypt(block cipher.Block, data []byte, opt IOption) ([]byte, error) {
    bs := block.BlockSize()

    // 补码
    newPadding, err := getPadding(opt)
    if err != nil {
        return nil, err
    }

    plainPadding := newPadding.Padding(data, bs, opt)

    // 补码后需要验证
    if opt.Padding() != NoPadding {
        if len(plainPadding)%bs != 0 {
            err := errors.New(fmt.Sprintf("Cryptobin: the length of the completed data must be an integer multiple of the block, the completed data size is %d, block size is %d", len(plainPadding), bs))
            return nil, err
        }
    }

    // 模式
    newMode, err := getMode(opt)
    if err != nil {
        return nil, err
    }

    return newMode.Encrypt(plainPadding, block, opt)
}

// 解密
func BlockDecrypt(block cipher.Block, data []byte, opt IOption) ([]byte, error) {
    bs := block.BlockSize()

    // 补码后需要验证
    if opt.Padding() != NoPadding {
        if len(data)%bs != 0 {
            err := errors.New(fmt.Sprintf("Cryptobin: improper decrypt type, block size is %d", bs))
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
    dst = newPadding.UnPadding(dst, opt)

    return dst, nil
}

// ===================

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
type EncryptAes struct {}

// 加密
func (this EncryptAes) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := aes.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密
func (this EncryptAes) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := aes.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptDes struct {}

// 加密
func (this EncryptDes) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := des.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密
func (this EncryptDes) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := des.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptTripleDes struct {}

// 加密
func (this EncryptTripleDes) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := des.NewTripleDESCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密
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

// 加密
func (this EncryptTwofish) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := twofish.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密
func (this EncryptTwofish) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := twofish.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptBlowfish struct {}

// 加密
func (this EncryptBlowfish) getBlock(opt IOption) (cipher.Block, error) {
    if opt.Config().Has("salt") {
        return blowfish.NewSaltedCipher(opt.Key(), opt.Config().GetBytes("salt"))
    }

    return blowfish.NewCipher(opt.Key())
}

// 加密
func (this EncryptBlowfish) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密
func (this EncryptBlowfish) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptTea struct {}

// 加密
func (this EncryptTea) getBlock(opt IOption) (cipher.Block, error) {
    // key is 16 bytes
    if opt.Config().Has("rounds") {
        return tea.NewCipherWithRounds(opt.Key(), opt.Config().GetInt("rounds"))
    }

    return tea.NewCipher(opt.Key())
}

// 加密
func (this EncryptTea) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密
func (this EncryptTea) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptXtea struct {}

// 加密
func (this EncryptXtea) getBlock(opt IOption) (cipher.Block, error) {
    // XTEA only supports 128 bit (16 byte) keys.
    return xtea.NewCipher(opt.Key())
}

// 加密
func (this EncryptXtea) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密
func (this EncryptXtea) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptCast5 struct {}

// 加密
func (this EncryptCast5) getBlock(opt IOption) (cipher.Block, error) {
    // Cast5 only supports 128 bit (16 byte) keys.
    return cast5.NewCipher(opt.Key())
}

// 加密
func (this EncryptCast5) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密
func (this EncryptCast5) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptRC2 struct {}

// 加密
func (this EncryptRC2) getBlock(opt IOption) (cipher.Block, error) {
    // RC2 key, at least 1 byte and at most 128 bytes.
    key := opt.Key()

    return cryptobin_rc2.NewCipher(key, len(key)*8)
}

// 加密
func (this EncryptRC2) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密
func (this EncryptRC2) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptRC5 struct {}

// 加密
func (this EncryptRC5) getBlock(opt IOption) (cipher.Block, error) {
    // wordSize is 32 or 64
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
    // iv is 8 with 32, 16 with 64
    return cryptobin_rc5.NewCipher(key, wordSize, rounds)
}

// 加密
func (this EncryptRC5) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密
func (this EncryptRC5) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

type EncryptSM4 struct {}

// 加密
func (this EncryptSM4) getBlock(opt IOption) (cipher.Block, error) {
    // 国密 sm4 加密
    return sm4.NewCipher(opt.Key())
}

// 加密
func (this EncryptSM4) Encrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockEncrypt(block, data, opt)
}

// 解密
func (this EncryptSM4) Decrypt(data []byte, opt IOption) ([]byte, error) {
    block, err := this.getBlock(opt)
    if err != nil {
        return nil, err
    }

    return BlockDecrypt(block, data, opt)
}

// ===================

// 32 bytes key and a 12 or 24 bytes nonce
type EncryptChacha20 struct {}

// 加密
func (this EncryptChacha20) Encrypt(data []byte, opt IOption) ([]byte, error) {
    if !opt.Config().Has("nonce") {
        err := fmt.Errorf("Cryptobin: chacha20 error: nonce is empty.")
        return nil, err
    }

    nonce := opt.Config().GetBytes("nonce")

    chacha, err := chacha20.NewUnauthenticatedCipher(opt.Key(), nonce)
    if err != nil {
        err := fmt.Errorf("Cryptobin: chacha20.New(),error:%w", err)
        return nil, err
    }

    if opt.Config().Has("counter") {
        chacha.SetCounter(opt.Config().GetUint32("counter"))
    }

    dst := make([]byte, len(data))

    chacha.XORKeyStream(dst, data)

    return dst, nil
}

// 解密
func (this EncryptChacha20) Decrypt(data []byte, opt IOption) ([]byte, error) {
    if !opt.Config().Has("nonce") {
        err := fmt.Errorf("Cryptobin: chacha20 error: nonce is empty.")
        return nil, err
    }

    nonce := opt.Config().GetBytes("nonce")

    chacha, err := chacha20.NewUnauthenticatedCipher(opt.Key(), nonce)
    if err != nil {
        err := fmt.Errorf("Cryptobin: chacha20.New(),error:%w", err)
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

// 加密
func (this EncryptChacha20poly1305) Encrypt(data []byte, opt IOption) ([]byte, error) {
    aead, err := chacha20poly1305.New(opt.Key())
    if err != nil {
        err := fmt.Errorf("Cryptobin: chacha20poly1305.New(),error:%w", err)
        return nil, err
    }

    if !opt.Config().Has("nonce") {
        err := fmt.Errorf("Cryptobin: chacha20poly1305 error: nonce is empty.")
        return nil, err
    }

    nonce := opt.Config().GetBytes("nonce")
    additional := opt.Config().GetBytes("additional")

    dst := aead.Seal(nil, nonce, data, additional)

    return dst, nil
}

// 解密
func (this EncryptChacha20poly1305) Decrypt(data []byte, opt IOption) ([]byte, error) {
    chacha, err := chacha20poly1305.New(opt.Key())
    if err != nil {
        err := fmt.Errorf("Cryptobin: chacha20poly1305.New(),error:%w", err)
        return nil, err
    }

    if !opt.Config().Has("nonce") {
        err := fmt.Errorf("Cryptobin: chacha20poly1305 error: nonce is empty.")
        return nil, err
    }

    nonce := opt.Config().GetBytes("nonce")
    additional := opt.Config().GetBytes("additional")

    return chacha.Open(nil, nonce, data, additional)
}

// ===================

// 32 bytes key
type EncryptChacha20poly1305X struct {}

// 加密
func (this EncryptChacha20poly1305X) Encrypt(data []byte, opt IOption) ([]byte, error) {
    aead, err := chacha20poly1305.NewX(opt.Key())
    if err != nil {
        err := fmt.Errorf("Cryptobin: chacha20poly1305.NewX(),error:%w", err)
        return nil, err
    }

    if !opt.Config().Has("nonce") {
        err := fmt.Errorf("Cryptobin: chacha20poly1305 error: nonce is empty.")
        return nil, err
    }

    nonce := opt.Config().GetBytes("nonce")
    additional := opt.Config().GetBytes("additional")

    dst := aead.Seal(nil, nonce, data, additional)

    return dst, nil
}

// 解密
func (this EncryptChacha20poly1305X) Decrypt(data []byte, opt IOption) ([]byte, error) {
    chacha, err := chacha20poly1305.NewX(opt.Key())
    if err != nil {
        err := fmt.Errorf("Cryptobin: chacha20poly1305.NewX(),error:%w", err)
        return nil, err
    }

    if !opt.Config().Has("nonce") {
        err := fmt.Errorf("Cryptobin: chacha20poly1305 error: nonce is empty.")
        return nil, err
    }

    nonce := opt.Config().GetBytes("nonce")
    additional := opt.Config().GetBytes("additional")

    return chacha.Open(nil, nonce, data, additional)
}

// ===================

// RC4 key, at least 1 byte and at most 256 bytes.
type EncryptRC4 struct {}

// 加密
func (this EncryptRC4) Encrypt(data []byte, opt IOption) ([]byte, error) {
    rc, err := rc4.NewCipher(opt.Key())
    if err != nil {
        err := fmt.Errorf("Cryptobin: rc4.NewCipher(),error:%w", err)
        return nil, err
    }

    dst := make([]byte, len(data))

    rc.XORKeyStream(dst, data)

    return dst, nil
}

// 解密
func (this EncryptRC4) Decrypt(data []byte, opt IOption) ([]byte, error) {
    rc, err := rc4.NewCipher(opt.Key())
    if err != nil {
        err := fmt.Errorf("Cryptobin: rc4.NewCipher(),error:%w", err)
        return nil, err
    }

    dst := make([]byte, len(data))

    rc.XORKeyStream(dst, data)

    return dst, nil
}

// ===================

// Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
type EncryptXts struct {}

// 加密
func (this EncryptXts) Encrypt(data []byte, opt IOption) ([]byte, error) {
    if !opt.Config().Has("cipher") {
        err := fmt.Errorf("Cryptobin: Xts error: cipher is empty.")
        return nil, err
    }

    if !opt.Config().Has("sector_num") {
        err := fmt.Errorf("Cryptobin: Xts error: sector_num is empty.")
        return nil, err
    }

    cipher := opt.Config().GetString("cipher")
    sectorNum := opt.Config().GetUint64("sector_num")

    cipherFunc := cryptobin_tool.NewCipher().GetFunc(cipher)

    xc, err := xts.NewCipher(cipherFunc, opt.Key())
    if err != nil {
        err := fmt.Errorf("Cryptobin: xts.NewCipher(),error:%w", err)
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

// 解密
func (this EncryptXts) Decrypt(data []byte, opt IOption) ([]byte, error) {
    if !opt.Config().Has("cipher") {
        err := fmt.Errorf("Cryptobin: Xts error: cipher is empty.")
        return nil, err
    }

    if !opt.Config().Has("sector_num") {
        err := fmt.Errorf("Cryptobin: Xts error: sector_num is empty.")
        return nil, err
    }

    cipher := opt.Config().GetString("cipher")
    sectorNum := opt.Config().GetUint64("sector_num")

    cipherFunc := cryptobin_tool.NewCipher().GetFunc(cipher)

    xc, err := xts.NewCipher(cipherFunc, opt.Key())
    if err != nil {
        err := fmt.Errorf("Cryptobin: xts.NewCipher(),error:%w", err)
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
    dst = newPadding.UnPadding(dst, opt)

    return dst, nil
}

// ===================

func init() {
    UseEncrypt.Add(Aes, func() IEncrypt {
        return EncryptAes{}
    })
    UseEncrypt.Add(Des, func() IEncrypt {
        return EncryptDes{}
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
    UseEncrypt.Add(RC5, func() IEncrypt {
        return EncryptRC5{}
    })
    UseEncrypt.Add(SM4, func() IEncrypt {
        return EncryptSM4{}
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
}
