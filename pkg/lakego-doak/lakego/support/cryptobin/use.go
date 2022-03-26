package cryptobin

// Aes
func (this Cryptobin) Aes() Cryptobin {
    this.multiple = "Aes"

    return this
}

// Des
func (this Cryptobin) Des() Cryptobin {
    this.multiple = "Des"

    return this
}

// TriDes
func (this Cryptobin) TriDes() Cryptobin {
    this.multiple = "TriDes"

    return this
}

// ==========

// ECB
func (this Cryptobin) ECB() Cryptobin {
    this.mode = "ECB"

    return this
}

// CBC
func (this Cryptobin) CBC() Cryptobin {
    this.mode = "CBC"

    return this
}

// CFB
func (this Cryptobin) CFB() Cryptobin {
    this.mode = "CFB"

    return this
}

// OFB
func (this Cryptobin) OFB() Cryptobin {
    this.mode = "OFB"

    return this
}

// CTR
func (this Cryptobin) CTR() Cryptobin {
    this.mode = "CTR"

    return this
}

// ==========

// Zero 补码
func (this Cryptobin) ZeroPadding() Cryptobin {
    this.padding = "Zero"

    return this
}

// PKCS5 补码
func (this Cryptobin) PKCS5Padding() Cryptobin {
    this.padding = "Pkcs5"

    return this
}

// PKCS7 补码
func (this Cryptobin) PKCS7Padding() Cryptobin {
    this.padding = "Pkcs7"

    return this
}

// ==========

// 向量
func (this Cryptobin) SetIv(data string) Cryptobin {
    this.iv = []byte(data)

    return this
}

// 密码
func (this Cryptobin) SetKey(data string) Cryptobin {
    this.key = []byte(data)

    return this
}
