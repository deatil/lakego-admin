package crypto

import (
    "fmt"
    "crypto/cipher"

    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
)

type ModeECB struct {}

// 加密
func (this ModeECB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewECBEncrypter(block).CryptBlocks(cryptText, plain)

    return cryptText, nil
}

// 解密
func (this ModeECB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    dst := make([]byte, len(data))
    cryptobin_cipher.NewECBDecrypter(block).CryptBlocks(dst, data)

    return dst, nil
}

// ===================

type ModeCBC struct {}

// 加密
func (this ModeCBC) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cipher.NewCBCEncrypter(block, iv).CryptBlocks(cryptText, plain)

    return cryptText, nil
}

// 解密
func (this ModeCBC) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, data)

    return dst, nil
}

// ===================

type ModePCBC struct {}

// 加密
func (this ModePCBC) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewPCBCEncrypter(block, iv).CryptBlocks(cryptText, plain)

    return cryptText, nil
}

// 解密
func (this ModePCBC) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewPCBCDecrypter(block, iv).CryptBlocks(dst, data)

    return dst, nil
}

// ===================

type ModeCFB struct {}

// 加密
func (this ModeCFB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cipher.NewCFBEncrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密
func (this ModeCFB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeCFB1 struct {}

// 加密
func (this ModeCFB1) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewCFB1Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密
func (this ModeCFB1) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewCFB1Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeCFB8 struct {}

// 加密
func (this ModeCFB8) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewCFB8Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密
func (this ModeCFB8) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewCFB8Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeCFB16 struct {}

// 加密
func (this ModeCFB16) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewCFB16Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密
func (this ModeCFB16) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewCFB16Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeCFB32 struct {}

// 加密
func (this ModeCFB32) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewCFB32Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密
func (this ModeCFB32) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewCFB32Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeCFB64 struct {}

// 加密
func (this ModeCFB64) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewCFB64Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密
func (this ModeCFB64) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewCFB64Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeOFB struct {}

// 加密
func (this ModeOFB) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cipher.NewOFB(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密
func (this ModeOFB) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cipher.NewOFB(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeOFB8 struct {}

// 加密
func (this ModeOFB8) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewOFB8(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密
func (this ModeOFB8) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewOFB8(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeCTR struct {}

// 加密
func (this ModeCTR) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cipher.NewCTR(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密
func (this ModeCTR) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // 向量
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cipher.NewCTR(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// ===================

type ModeGCM struct {}

// 加密
func (this ModeGCM) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("Cryptobin: GCM error:nonce is empty.")
        return nil, err
    }

    aead, err := cipher.NewGCMWithNonceSize(block, len(nonceBytes))
    if err != nil {
        err = fmt.Errorf("Cryptobin: cipher.NewGCMWithNonceSize(),error:%w", err)
        return nil, err
    }

    additionalBytes := opt.Config().GetBytes("additional")

    cryptText := aead.Seal(nil, nonceBytes, plain, additionalBytes)

    return cryptText, nil
}

// 解密
func (this ModeGCM) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("Cryptobin: CCM error:nonce is empty.")
        return nil, err
    }

    aead, err := cipher.NewGCMWithNonceSize(block, len(nonceBytes))
    if err != nil {
        err = fmt.Errorf("Cryptobin: cipher.NewGCMWithNonceSize(),error:%w", err)
        return nil, err
    }

    additionalBytes := opt.Config().GetBytes("additional")

    dst, err := aead.Open(nil, nonceBytes, data, additionalBytes)

    return dst, err
}

// ===================

type ModeCCM struct {}

// 加密
func (this ModeCCM) Encrypt(plain []byte, block cipher.Block, opt IOption) ([]byte, error) {
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("Cryptobin: CCM error:nonce is empty.")
        return nil, err
    }

    aead, err := cryptobin_cipher.NewCCMWithNonceSize(block, len(nonceBytes))
    if err != nil {
        err = fmt.Errorf("Cryptobin: cipher.NewCCMWithNonceSize(),error:%w", err)
        return nil, err
    }

    additionalBytes := opt.Config().GetBytes("additional")

    cryptText := aead.Seal(nil, nonceBytes, plain, additionalBytes)

    return cryptText, nil
}

// 解密
func (this ModeCCM) Decrypt(data []byte, block cipher.Block, opt IOption) ([]byte, error) {
    // ccm nounce size, should be in [7,13]
    nonceBytes := opt.Config().GetBytes("nonce")
    if nonceBytes == nil {
        err := fmt.Errorf("Cryptobin: GCM error:nonce is empty.")
        return nil, err
    }

    aead, err := cryptobin_cipher.NewCCMWithNonceSize(block, len(nonceBytes))
    if err != nil {
        err = fmt.Errorf("Cryptobin: cipher.NewCCMWithNonceSize(),error:%w", err)
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
