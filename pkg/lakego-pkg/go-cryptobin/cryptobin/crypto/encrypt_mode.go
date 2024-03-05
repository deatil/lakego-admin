package crypto

import (
    "fmt"
    "errors"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool"
    "github.com/deatil/go-cryptobin/cipher/ocb"
    "github.com/deatil/go-cryptobin/cipher/eax"
    "github.com/deatil/go-cryptobin/cipher/ccm"
    "github.com/deatil/go-cryptobin/cipher/hctr"
    "github.com/deatil/go-cryptobin/cipher/mgm"
    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
)

type ModeECB struct {}

// 加密 / Encrypt
func (this ModeECB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewECBEncrypter(block).CryptBlocks(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeECB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    dst := make([]byte, len(data))
    cryptobin_cipher.NewECBDecrypter(block).CryptBlocks(dst, data)

    return dst, nil
}

// ===================

type ModeCBC struct {}

// 加密 / Encrypt
func (this ModeCBC) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cipher.NewCBCEncrypter(block, iv).CryptBlocks(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCBC) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, data)

    return dst, nil
}

// ===================

type ModePCBC struct {}

// 加密 / Encrypt
func (this ModePCBC) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewPCBCEncrypter(block, iv).CryptBlocks(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModePCBC) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewPCBCDecrypter(block, iv).CryptBlocks(dst, data)

    return dst, nil
}

// ===================

type ModeCFB struct {}

// 加密 / Encrypt
func (this ModeCFB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cipher.NewCFBEncrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCFB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeCFB1 struct {}

// 加密 / Encrypt
func (this ModeCFB1) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewCFB1Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCFB1) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewCFB1Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeCFB8 struct {}

// 加密 / Encrypt
func (this ModeCFB8) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewCFB8Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCFB8) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewCFB8Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeCFB16 struct {}

// 加密 / Encrypt
func (this ModeCFB16) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewCFB16Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCFB16) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewCFB16Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeCFB32 struct {}

// 加密 / Encrypt
func (this ModeCFB32) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewCFB32Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCFB32) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewCFB32Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeCFB64 struct {}

// 加密 / Encrypt
func (this ModeCFB64) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewCFB64Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCFB64) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewCFB64Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeOFB struct {}

// 加密 / Encrypt
func (this ModeOFB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cipher.NewOFB(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeOFB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cipher.NewOFB(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeOFB8 struct {}

// 加密 / Encrypt
func (this ModeOFB8) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewOFB8(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeOFB8) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewOFB8(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeCTR struct {}

// 加密 / Encrypt
func (this ModeCTR) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cipher.NewCTR(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCTR) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cipher.NewCTR(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeGCM struct {}

// 加密 / Encrypt
func (this ModeGCM) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("nonce is empty.")
        return nil, err
    }

    aead, err := cipher.NewGCMWithNonceSize(block, len(nonceBytes))
    if err != nil {
        return nil, err
    }

    additionalBytes := opt.Config().GetBytes("additional")

    cryptText := aead.Seal(nil, nonceBytes, plain, additionalBytes)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeGCM) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("nonce is empty.")
        return nil, err
    }

    aead, err := cipher.NewGCMWithNonceSize(block, len(nonceBytes))
    if err != nil {
        return nil, err
    }

    additionalBytes := opt.Config().GetBytes("additional")

    dst, err := aead.Open(nil, nonceBytes, data, additionalBytes)

    return dst, err
}

// ===================

type ModeCCM struct {}

// 加密 / Encrypt
func (this ModeCCM) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("nonce is empty.")
        return nil, err
    }

    aead, err := ccm.NewCCMWithNonceSize(block, len(nonceBytes))
    if err != nil {
        return nil, err
    }

    additionalBytes := opt.Config().GetBytes("additional")

    cryptText := aead.Seal(nil, nonceBytes, plain, additionalBytes)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCCM) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // ccm nounce size, should be in [7,13]
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("nonce is empty.")
        return nil, err
    }

    aead, err := ccm.NewCCMWithNonceSize(block, len(nonceBytes))
    if err != nil {
        return nil, err
    }

    additionalBytes := opt.Config().GetBytes("additional")

    dst, err := aead.Open(nil, nonceBytes, data, additionalBytes)

    return dst, err
}

// ===================

func init() {
    UseMode.Add(ECB, func() IMode {
        return ModeECB{}
    })
    UseMode.Add(CBC, func() IMode {
        return ModeCBC{}
    })
    UseMode.Add(PCBC, func() IMode {
        return ModePCBC{}
    })
    UseMode.Add(CFB, func() IMode {
        return ModeCFB{}
    })
    UseMode.Add(CFB1, func() IMode {
        return ModeCFB1{}
    })
    UseMode.Add(CFB8, func() IMode {
        return ModeCFB8{}
    })
    UseMode.Add(CFB16, func() IMode {
        return ModeCFB16{}
    })
    UseMode.Add(CFB32, func() IMode {
        return ModeCFB32{}
    })
    UseMode.Add(CFB64, func() IMode {
        return ModeCFB64{}
    })
    UseMode.Add(CFB128, func() IMode {
        return ModeCFB{}
    })
    UseMode.Add(OFB, func() IMode {
        return ModeOFB{}
    })
    UseMode.Add(OFB8, func() IMode {
        return ModeOFB8{}
    })
    UseMode.Add(CTR, func() IMode {
        return ModeCTR{}
    })
    UseMode.Add(GCM, func() IMode {
        return ModeGCM{}
    })
    UseMode.Add(CCM, func() IMode {
        return ModeCCM{}
    })
}

// ===================

// OCFB 模式不需要补码
// 默认 prefix 放置在结果数据之前
// OCFB not need padding and return [prefix + encrypted]
type ModeOCFB struct {}

// 加密 / Encrypt
func (this ModeOCFB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    blockSize := block.BlockSize()

    randData, _ := tool.GenRandom(blockSize)

    resync := opt.Config().GetBool("resync")

    mode, prefix := cryptobin_cipher.NewOCFBEncrypter(block, randData, cryptobin_cipher.OCFBResyncOption(resync))
    if mode == nil {
        return nil, errors.New("cipher: randData length is not eq blockSize.")
    }

    // prefix 长度
    prefixLen := blockSize+2

    cryptText := make([]byte, len(plain) + prefixLen)
    mode.XORKeyStream(cryptText[prefixLen:], plain)

    copy(cryptText[:prefixLen], prefix)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeOCFB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    blockSize := block.BlockSize()

    // prefix 长度
    prefixLen := blockSize+2

    if len(data) < prefixLen {
        return nil, errors.New("cipher: data is too short.")
    }

    prefix := data[:prefixLen]

    resync := opt.Config().GetBool("resync")

    mode := cryptobin_cipher.NewOCFBDecrypter(block, prefix, cryptobin_cipher.OCFBResyncOption(resync))
    if mode == nil {
        return nil, errors.New("cipher: prefix length is not eq blockSize + 2.")
    }

    dst := make([]byte, len(data) - prefixLen)
    mode.XORKeyStream(dst, data[prefixLen:])

    return dst, nil
}

func init() {
    UseMode.Add(OCFB, func() IMode {
        return ModeOCFB{}
    })
}

// ===================

type ModeOCB struct {}

// 加密 / Encrypt
func (this ModeOCB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("nonce is empty.")
        return nil, err
    }

    aead, err := ocb.NewOCBWithNonceSize(block, len(nonceBytes))
    if err != nil {
        return nil, err
    }

    additionalBytes := opt.Config().GetBytes("additional")

    cryptText := aead.Seal(nil, nonceBytes, plain, additionalBytes)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeOCB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // ocb nounce size, should be in [0, cipher.block.BlockSize]
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("nonce is empty.")
        return nil, err
    }

    aead, err := ocb.NewOCBWithNonceSize(block, len(nonceBytes))
    if err != nil {
        return nil, err
    }

    additionalBytes := opt.Config().GetBytes("additional")

    dst, err := aead.Open(nil, nonceBytes, data, additionalBytes)

    return dst, err
}

func init() {
    UseMode.Add(OCB, func() IMode {
        return ModeOCB{}
    })
}

// ===================

type ModeEAX struct {}

// 加密 / Encrypt
func (this ModeEAX) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("nonce is empty.")
        return nil, err
    }

    aead, err := eax.NewEAXWithNonceSize(block, len(nonceBytes))
    if err != nil {
        return nil, err
    }

    additionalBytes := opt.Config().GetBytes("additional")

    cryptText := aead.Seal(nil, nonceBytes, plain, additionalBytes)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeEAX) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // eax nounce size, should be in > 0
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("nonce is empty.")
        return nil, err
    }

    aead, err := eax.NewEAXWithNonceSize(block, len(nonceBytes))
    if err != nil {
        return nil, err
    }

    additionalBytes := opt.Config().GetBytes("additional")

    dst, err := aead.Open(nil, nonceBytes, data, additionalBytes)

    return dst, err
}

func init() {
    UseMode.Add(EAX, func() IMode {
        return ModeOCB{}
    })
}

// ===================

type ModeNCFB struct {}

// 加密 / Encrypt
func (this ModeNCFB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewNCFBEncrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeNCFB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewNCFBDecrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

func init() {
    UseMode.Add(NCFB, func() IMode {
        return ModeNCFB{}
    })
}

// ===================

type ModeNOFB struct {}

// 加密 / Encrypt
func (this ModeNOFB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewNOFB(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeNOFB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewNOFB(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

func init() {
    UseMode.Add(NOFB, func() IMode {
        return ModeNOFB{}
    })
}

// ===================

type ModeBC struct {}

// 加密 / Encrypt
func (this ModeBC) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewBCEncrypter(block, iv).CryptBlocks(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeBC) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewBCDecrypter(block, iv).CryptBlocks(dst, data)

    return dst, nil
}

func init() {
    UseMode.Add(BC, func() IMode {
        return ModeBC{}
    })
}

// ===================

type ModeHCTR struct {}

// 加密 / Encrypt
func (this ModeHCTR) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    tweak := opt.Config().GetBytes("tweak")
    hkey := opt.Config().GetBytes("hkey")

    cryptText := make([]byte, len(plain))
    hctr.NewHCTR(block, tweak, hkey).Encrypt(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeHCTR) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    tweak := opt.Config().GetBytes("tweak")
    hkey := opt.Config().GetBytes("hkey")

    dst := make([]byte, len(data))
    hctr.NewHCTR(block, tweak, hkey).Decrypt(dst, data)

    return dst, nil
}

func init() {
    UseMode.Add(HCTR, func() IMode {
        return ModeHCTR{}
    })
}

// ===================

type ModeMGM struct {}

// 加密 / Encrypt
func (this ModeMGM) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("nonce is empty.")
        return nil, err
    }

    aead, err := mgm.NewMGM(block)
    if err != nil {
        return nil, err
    }

    additionalBytes := opt.Config().GetBytes("additional")

    cryptText := aead.Seal(nil, nonceBytes, plain, additionalBytes)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeMGM) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("nonce is empty.")
        return nil, err
    }

    aead, err := mgm.NewMGM(block)
    if err != nil {
        return nil, err
    }

    additionalBytes := opt.Config().GetBytes("additional")

    dst, err := aead.Open(nil, nonceBytes, data, additionalBytes)

    return dst, err
}

func init() {
    UseMode.Add(MGM, func() IMode {
        return ModeMGM{}
    })
}

// ===================

type ModeGOFB struct {}

// 加密 / Encrypt
func (this ModeGOFB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewGOFB(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeGOFB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewGOFB(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

func init() {
    UseMode.Add(GOFB, func() IMode {
        return ModeGOFB{}
    })
}

// ===================

type ModeG3413CBC struct {}

// 加密 / Encrypt
func (this ModeG3413CBC) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewG3413CBCEncrypter(block, iv).CryptBlocks(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeG3413CBC) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewG3413CBCDecrypter(block, iv).CryptBlocks(dst, data)

    return dst, nil
}

func init() {
    UseMode.Add(G3413CBC, func() IMode {
        return ModeG3413CBC{}
    })
}

// ===================

type ModeG3413CFB struct {}

// 加密 / Encrypt
func (this ModeG3413CFB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))

    bitBlockSize := opt.Config().GetInt("bit_block_size")
    if bitBlockSize > 0 {
        cryptobin_cipher.NewG3413CFBEncrypterWithBitBlockSize(block, iv, bitBlockSize).
            XORKeyStream(cryptText, plain)
    } else {
        cryptobin_cipher.NewG3413CFBEncrypter(block, iv).
            XORKeyStream(cryptText, plain)
    }

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeG3413CFB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))

    bitBlockSize := opt.Config().GetInt("bit_block_size")
    if bitBlockSize > 0 {
        cryptobin_cipher.NewG3413CFBDecrypterWithBitBlockSize(block, iv, bitBlockSize).
            XORKeyStream(dst, data)
    } else {
        cryptobin_cipher.NewG3413CFBDecrypter(block, iv).
            XORKeyStream(dst, data)
    }

    return dst, nil
}

func init() {
    UseMode.Add(G3413CFB, func() IMode {
        return ModeG3413CFB{}
    })
}

// ===================

type ModeG3413CTR struct {}

// 加密 / Encrypt
func (this ModeG3413CTR) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))

    bitBlockSize := opt.Config().GetInt("bit_block_size")
    if bitBlockSize > 0 {
        cryptobin_cipher.NewG3413CTRWithBitBlockSize(block, iv, bitBlockSize).
            XORKeyStream(cryptText, plain)
    } else {
        cryptobin_cipher.NewG3413CTR(block, iv).
            XORKeyStream(cryptText, plain)
    }

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeG3413CTR) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))

    bitBlockSize := opt.Config().GetInt("bit_block_size")
    if bitBlockSize > 0 {
        cryptobin_cipher.NewG3413CTRWithBitBlockSize(block, iv, bitBlockSize).
            XORKeyStream(dst, data)
    } else {
        cryptobin_cipher.NewG3413CTR(block, iv).
            XORKeyStream(dst, data)
    }

    return dst, nil
}

func init() {
    UseMode.Add(G3413CTR, func() IMode {
        return ModeG3413CTR{}
    })
}

// ===================

type ModeG3413OFB struct {}

// 加密 / Encrypt
func (this ModeG3413OFB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewG3413OFB(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeG3413OFB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewG3413OFB(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

func init() {
    UseMode.Add(G3413OFB, func() IMode {
        return ModeG3413CBC{}
    })
}
