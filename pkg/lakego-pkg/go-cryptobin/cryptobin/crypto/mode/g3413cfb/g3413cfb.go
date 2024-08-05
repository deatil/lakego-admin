package g3413cfb

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
)

type ModeG3413CFB struct {}

// 加密 / Encrypt
func (this ModeG3413CFB) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
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
func (this ModeG3413CFB) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
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

// G3413CFB
var G3413CFB = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(G3413CFB, func() string {
        return "G3413CFB"
    })

    crypto.UseMode.Add(G3413CFB, func() crypto.IMode {
        return ModeG3413CFB{}
    })
}
