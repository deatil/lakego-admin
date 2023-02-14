package crypto

// Aes
func (this Cryptobin) Aes() Cryptobin {
    this.multiple = Aes

    return this
}

// Des
func (this Cryptobin) Des() Cryptobin {
    this.multiple = Des

    return this
}

// TriDes
func (this Cryptobin) TriDes() Cryptobin {
    this.multiple = TriDes

    return this
}

// Twofish
func (this Cryptobin) Twofish() Cryptobin {
    this.multiple = Twofish

    return this
}

// Blowfish
func (this Cryptobin) Blowfish(salt ...string) Cryptobin {
    this.multiple = Blowfish

    if len(salt) > 0 {
        this.config.Set("salt", []byte(salt[0]))
    }

    return this
}

// Tea
func (this Cryptobin) Tea(rounds ...int) Cryptobin {
    this.multiple = Tea

    if len(rounds) > 0 {
        this.config.Set("rounds", rounds[0])
    }

    return this
}

// Xtea
func (this Cryptobin) Xtea() Cryptobin {
    this.multiple = Xtea

    return this
}

// Cast5
func (this Cryptobin) Cast5() Cryptobin {
    this.multiple = Cast5

    return this
}

// SM4
func (this Cryptobin) SM4() Cryptobin {
    this.multiple = SM4

    return this
}

// Chacha20
func (this Cryptobin) Chacha20(nonce string, counter ...uint32) Cryptobin {
    this.multiple = Chacha20

    this.config.Set("nonce", []byte(nonce))

    if len(counter) > 0 {
        this.config.Set("counter", counter[0])
    }

    return this
}

// Chacha20poly1305
// nonce is 12 bytes
func (this Cryptobin) Chacha20poly1305(nonce string, additional string) Cryptobin {
    this.multiple = Chacha20poly1305

    this.config.Set("nonce", []byte(nonce))
    this.config.Set("additional", []byte(additional))

    return this
}

// Chacha20poly1305X
// nonce is 24 bytes
func (this Cryptobin) Chacha20poly1305X(nonce string, additional string) Cryptobin {
    this.multiple = Chacha20poly1305X

    this.config.Set("nonce", []byte(nonce))
    this.config.Set("additional", []byte(additional))

    return this
}

// RC2
func (this Cryptobin) RC2() Cryptobin {
    this.multiple = RC2

    return this
}

// RC4
func (this Cryptobin) RC4() Cryptobin {
    this.multiple = RC4

    return this
}

// RC5
func (this Cryptobin) RC5(wordSize, rounds uint) Cryptobin {
    this.multiple = RC5

    this.config.Set("word_size", wordSize)
    this.config.Set("rounds", rounds)

    return this
}

// Xts
// cipher 可用 [ Aes | Des | TriDes | Tea | Xtea | Twofish | Blowfish | Cast5 | SM4]
func (this Cryptobin) Xts(cipher string, sectorNum uint64) Cryptobin {
    this.multiple = Xts

    this.config.Set("cipher", cipher)
    this.config.Set("sector_num", sectorNum)

    return this
}

// ==========

// 电码本模式
func (this Cryptobin) ECB() Cryptobin {
    this.mode = ECB

    return this
}

// 密码分组链接模式
func (this Cryptobin) CBC() Cryptobin {
    this.mode = CBC

    return this
}

// 密码反馈模式
func (this Cryptobin) CFB() Cryptobin {
    this.mode = CFB

    return this
}

// 密码反馈模式, 8字节
func (this Cryptobin) CFB8() Cryptobin {
    this.mode = CFB8

    return this
}

// 输出反馈模式
func (this Cryptobin) OFB() Cryptobin {
    this.mode = OFB

    return this
}

// 输出反馈模式, 8字节
func (this Cryptobin) OFB8() Cryptobin {
    this.mode = OFB8

    return this
}

// 计算器模式
func (this Cryptobin) CTR() Cryptobin {
    this.mode = CTR

    return this
}

// GCM
func (this Cryptobin) GCM(nonce string, additional ...string) Cryptobin {
    this.mode = GCM

    this.config.Set("nonce", []byte(nonce))

    if len(additional) > 0 {
        this.config.Set("additional", []byte(additional[0]))
    }

    return this
}

// CCM
// ccm nounce size, should be in [7,13]
func (this Cryptobin) CCM(nonce string, additional ...string) Cryptobin {
    this.mode = CCM

    this.config.Set("nonce", []byte(nonce))

    if len(additional) > 0 {
        this.config.Set("additional", []byte(additional[0]))
    }

    return this
}

// ==========

// 不补码
func (this Cryptobin) NoPadding() Cryptobin {
    this.padding = NoPadding

    return this
}

// Zero 补码
func (this Cryptobin) ZeroPadding() Cryptobin {
    this.padding = ZeroPadding

    return this
}

// PKCS5 补码
func (this Cryptobin) PKCS5Padding() Cryptobin {
    this.padding = PKCS5Padding

    return this
}

// PKCS7 补码
func (this Cryptobin) PKCS7Padding() Cryptobin {
    this.padding = PKCS7Padding

    return this
}

// X923 补码
func (this Cryptobin) X923Padding() Cryptobin {
    this.padding = X923Padding

    return this
}

// ISO10126 补码
func (this Cryptobin) ISO10126Padding() Cryptobin {
    this.padding = ISO10126Padding

    return this
}

// ISO7816_4 补码
func (this Cryptobin) ISO7816_4Padding() Cryptobin {
    this.padding = ISO7816_4Padding

    return this
}

// ISO97971 补码
func (this Cryptobin) ISO97971Padding() Cryptobin {
    this.padding = ISO97971Padding

    return this
}

// TBC 补码
func (this Cryptobin) TBCPadding() Cryptobin {
    this.padding = TBCPadding

    return this
}

// PKCS1 补码
func (this Cryptobin) PKCS1Padding(bt ...string) Cryptobin {
    this.padding = PKCS1Padding

    if len(bt) > 0 {
        this.config.Set("pkcs1_padding_bt", bt[0])
    }

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
