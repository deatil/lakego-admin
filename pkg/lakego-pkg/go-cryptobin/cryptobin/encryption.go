package cryptobin

// 加密
func (this Cryptobin) Encrypt() Cryptobin {
    switch this.multiple {
        // 不通用的处理
        case "Chacha20",
            "Chacha20poly1305",
            "RC4":
            return this.GuessEncrypt()
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
            return this.GuessDecrypt()
        // 默认通用
        default:
            return this.CipherDecrypt()
    }
}

// ====================

// 方法加密
func (this Cryptobin) FuncEncrypt(f func(Cryptobin) Cryptobin) Cryptobin {
    return f(this)
}

// 方法解密
func (this Cryptobin) FuncDecrypt(f func(Cryptobin) Cryptobin) Cryptobin {
    return f(this)
}
