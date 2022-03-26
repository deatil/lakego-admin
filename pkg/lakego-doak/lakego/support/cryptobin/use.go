package cryptobin

// Aes
func (this Crypto) Aes() Crypto {
    this.Type = "Aes"

    return this
}

// Des
func (this Crypto) Des() Crypto {
    this.Type = "Des"

    return this
}

// TriDes
func (this Crypto) TriDes() Crypto {
    this.Type = "TriDes"

    return this
}

// ==========

// ECB
func (this Crypto) ECB() Crypto {
    this.Mode = "ECB"

    return this
}

// CBC
func (this Crypto) CBC() Crypto {
    this.Mode = "CBC"

    return this
}

// CFB
func (this Crypto) CFB() Crypto {
    this.Mode = "CFB"

    return this
}

// OFB
func (this Crypto) OFB() Crypto {
    this.Mode = "OFB"

    return this
}

// CTR
func (this Crypto) CTR() Crypto {
    this.Mode = "CTR"

    return this
}

// ==========

// ZeroPadding
func (this Crypto) ZeroPadding() Crypto {
    this.Padding = "Zero"

    return this
}

// PKCS5Padding
func (this Crypto) PKCS5Padding() Crypto {
    this.Padding = "Pkcs5"

    return this
}

// PKCS7Padding
func (this Crypto) PKCS7Padding() Crypto {
    this.Padding = "Pkcs7"

    return this
}

// ==========

// SetIv
func (this Crypto) SetIv(data string) Crypto {
    this.Iv = []byte(data)

    return this
}

// SetKey
func (this Crypto) SetKey(data string) Crypto {
    this.Key = []byte(data)

    return this
}
