package g3413ctr

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
)

type ModeG3413CTR struct {}

// 加密 / Encrypt
func (this ModeG3413CTR) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
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
func (this ModeG3413CTR) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
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

// G3413CTR
var G3413CTR = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(G3413CTR, func() string {
        return "G3413CTR"
    })

    crypto.UseMode.Add(G3413CTR, func() crypto.IMode {
        return ModeG3413CTR{}
    })
}
