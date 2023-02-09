package crypto

// 加密
func (this Cryptobin) Encrypt() Cryptobin {
    guessMultiple := this.CheckGuessMultiple()
    if guessMultiple {
        return this.GuessEncrypt()
    } else {
        return this.CipherEncrypt()
    }
}

// 解密
func (this Cryptobin) Decrypt() Cryptobin {
    guessMultiple := this.CheckGuessMultiple()
    if guessMultiple {
        return this.GuessDecrypt()
    } else {
        return this.CipherDecrypt()
    }
}

// 检测 guess 方式
func (this Cryptobin) CheckGuessMultiple() bool {
    switch this.multiple {
        // 不通用的处理
        case Chacha20,
            Chacha20poly1305,
            Chacha20poly1305X,
            RC4,
            Xts:
            return true
        // 默认通用
        default:
            return false
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
