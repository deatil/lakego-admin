package cryptobin

// 加密
func (this Cryptobin) Encrypt() Cryptobin {
    switch this.multiple {
        // 不通用的处理
        case "Chacha20",
            "Chacha20poly1305",
            "RC4":
            return this.AEADEncrypt()
        // 默认通用
        default:
            return this.CipherEncrypt()
    }
}

// 解密
func (this Cryptobin) Decrypt() Cryptobin {
    switch this.multiple {
        // 不通用的处理
        case "Chacha20",
            "Chacha20poly1305",
            "RC4":
            return this.AEADDecrypt()
        // 默认通用
        default:
            return this.CipherDecrypt()
    }
}
