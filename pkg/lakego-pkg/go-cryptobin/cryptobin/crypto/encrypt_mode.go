package crypto

import (
    "errors"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/mode/ccm"
    "github.com/deatil/go-cryptobin/mode/hctr"
    "github.com/deatil/go-cryptobin/tool/utils"
    cryptobin_mode "github.com/deatil/go-cryptobin/mode"
)

type ModeECB struct {}

// 加密 / Encrypt
func (this ModeECB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    cryptText := make([]byte, len(plain))
    cryptobin_mode.NewECBEncrypter(block).CryptBlocks(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeECB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    dst := make([]byte, len(data))
    cryptobin_mode.NewECBDecrypter(block).CryptBlocks(dst, data)

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
    cryptobin_mode.NewPCBCEncrypter(block, iv).CryptBlocks(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModePCBC) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_mode.NewPCBCDecrypter(block, iv).CryptBlocks(dst, data)

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
    cryptobin_mode.NewCFB1Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCFB1) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_mode.NewCFB1Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeCFB8 struct {}

// 加密 / Encrypt
func (this ModeCFB8) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_mode.NewCFB8Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCFB8) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_mode.NewCFB8Decrypter(block, iv).XORKeyStream(dst, data)

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
    cryptobin_mode.NewOFB8(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeOFB8) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_mode.NewOFB8(block, iv).XORKeyStream(dst, data)

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
    var aead cipher.AEAD
    var err error

    iv := opt.Iv()

    tagSize := opt.Config().GetInt("tagSize")
    if tagSize > 0 {
        aead, err = cipher.NewGCMWithTagSize(block, tagSize)
    } else {
        aead, err = cipher.NewGCMWithNonceSize(block, len(iv))
    }

    if err != nil {
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")

    cryptText := aead.Seal(nil, iv, plain, additional)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeGCM) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    var aead cipher.AEAD
    var err error

    iv := opt.Iv()

    tagSize := opt.Config().GetInt("tagSize")
    if tagSize > 0 {
        aead, err = cipher.NewGCMWithTagSize(block, tagSize)
    } else {
        aead, err = cipher.NewGCMWithNonceSize(block, len(iv))
    }

    if err != nil {
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")

    dst, err := aead.Open(nil, iv, data, additional)

    return dst, err
}

// ===================

type ModeCCM struct {}

// 加密 / Encrypt
func (this ModeCCM) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    var aead cipher.AEAD
    var err error

    iv := opt.Iv()

    tagSize := opt.Config().GetInt("tagSize")
    if tagSize > 0 {
        aead, err = ccm.NewCCMWithTagSize(block, tagSize)
    } else {
        aead, err = ccm.NewCCMWithNonceSize(block, len(iv))
    }

    if err != nil {
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")

    cryptText := aead.Seal(nil, iv, plain, additional)

    return cryptText, nil
}

// 解密 / Decrypt
// ccm nounce size, should be in [7,13]
func (this ModeCCM) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    var aead cipher.AEAD
    var err error

    iv := opt.Iv()

    tagSize := opt.Config().GetInt("tagSize")
    if tagSize > 0 {
        aead, err = ccm.NewCCMWithTagSize(block, tagSize)
    } else {
        aead, err = ccm.NewCCMWithNonceSize(block, len(iv))
    }

    additional := opt.Config().GetBytes("additional")

    dst, err := aead.Open(nil, iv, data, additional)

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

    randData, _ := utils.GenRandom(blockSize)

    resync := opt.Config().GetBool("resync")

    mode, prefix := cryptobin_mode.NewOCFBEncrypter(block, randData, cryptobin_mode.OCFBResyncOption(resync))
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

    mode := cryptobin_mode.NewOCFBDecrypter(block, prefix, cryptobin_mode.OCFBResyncOption(resync))
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

type ModeBC struct {}

// 加密 / Encrypt
func (this ModeBC) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_mode.NewBCEncrypter(block, iv).CryptBlocks(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeBC) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_mode.NewBCDecrypter(block, iv).CryptBlocks(dst, data)

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
