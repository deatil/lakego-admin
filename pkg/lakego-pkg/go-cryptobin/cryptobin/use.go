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

// Twofish
func (this Cryptobin) Twofish() Cryptobin {
    this.multiple = "Twofish"

    return this
}

// Blowfish
func (this Cryptobin) Blowfish(salt ...[]byte) Cryptobin {
    this.multiple = "Blowfish"

    if len(salt) > 0 {
        this.config["salt"] = salt[0]
    }

    return this
}

// Tea
func (this Cryptobin) Tea(rounds ...int) Cryptobin {
    this.multiple = "Tea"

    if len(rounds) > 0 {
        this.config["rounds"] = rounds[0]
    }

    return this
}

// Xtea
func (this Cryptobin) Xtea() Cryptobin {
    this.multiple = "Xtea"

    return this
}

// Cast5
func (this Cryptobin) Cast5() Cryptobin {
    this.multiple = "Cast5"

    return this
}

// Chacha20
func (this Cryptobin) Chacha20(nonce []byte, counter ...uint32) Cryptobin {
    this.multiple = "Chacha20"

    this.config["nonce"] = nonce

    if len(counter) > 0 {
        this.config["counter"] = counter[0]
    }

    return this
}

// Chacha20poly1305
// nonce is 12 bytes
func (this Cryptobin) Chacha20poly1305(nonce []byte, additional []byte) Cryptobin {
    this.multiple = "Chacha20poly1305"

    this.config["nonce"] = nonce
    this.config["additional"] = additional

    return this
}

// RC4
func (this Cryptobin) RC4() Cryptobin {
    this.multiple = "RC4"

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

// GCM
func (this Cryptobin) GCM(nonce []byte, additional []byte) Cryptobin {
    this.mode = "GCM"

    this.config["nonce"] = nonce
    this.config["additional"] = additional

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

// 不补码
func (this Cryptobin) NoPadding() Cryptobin {
    this.padding = ""

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

// ==========

// 不做处理
func (this Cryptobin) NoParse() Cryptobin {
    this.parsedData = this.data

    return this
}
