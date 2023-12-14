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

// TwoDes
func (this Cryptobin) TwoDes() Cryptobin {
    this.multiple = TwoDes

    return this
}

// TripleDes
func (this Cryptobin) TripleDes() Cryptobin {
    this.multiple = TripleDes

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

// Cast256
// The key argument should be 32 bytes.
func (this Cryptobin) Cast256() Cryptobin {
    this.multiple = Cast256

    return this
}

// Idea
func (this Cryptobin) Idea() Cryptobin {
    this.multiple = Idea

    return this
}

// SM4
func (this Cryptobin) SM4() Cryptobin {
    this.multiple = SM4

    return this
}

// Chacha20 | Chacha20IETF | XChacha20
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

// RC4MD5
func (this Cryptobin) RC4MD5() Cryptobin {
    this.multiple = RC4MD5

    return this
}

// RC5
func (this Cryptobin) RC5(wordSize, rounds uint) Cryptobin {
    this.multiple = RC5

    this.config.Set("word_size", wordSize)
    this.config.Set("rounds", rounds)

    return this
}

// RC6
func (this Cryptobin) RC6() Cryptobin {
    this.multiple = RC6

    return this
}

// Xts
// cipher 可用 [ Aes | Des | TripleDes | Tea | Xtea | Twofish | Blowfish | Cast5 | SM4]
func (this Cryptobin) Xts(cipher string, sectorNum uint64) Cryptobin {
    this.multiple = Xts

    this.config.Set("cipher", cipher)
    this.config.Set("sector_num", sectorNum)

    return this
}

// Salsa20
// key is 32 bytes, nonce is 16 bytes.
func (this Cryptobin) Salsa20(nonce string) Cryptobin {
    this.multiple = Salsa20

    this.config.Set("nonce", []byte(nonce))

    return this
}

// Seed
// The key argument should be 16 bytes.
func (this Cryptobin) Seed() Cryptobin {
    this.multiple = Seed

    return this
}

// Aria
// key is 16, 24, or 32 bytes.
func (this Cryptobin) Aria() Cryptobin {
    this.multiple = Aria

    return this
}

// Camellia
// The key argument should be 16, 24, or 32 bytes.
func (this Cryptobin) Camellia() Cryptobin {
    this.multiple = Camellia

    return this
}

// Gost
// The key argument should be 32 bytes.
// sbox is [DESDerivedSbox | TestSbox | CryptoProSbox | TC26Sbox | EACSbox]
// or set [][]byte data
func (this Cryptobin) Gost(sbox any) Cryptobin {
    this.multiple = Gost

    this.config.Set("sbox", sbox)

    return this
}

// Kuznyechik
// The key argument should be 32 bytes.
func (this Cryptobin) Kuznyechik() Cryptobin {
    this.multiple = Kuznyechik

    return this
}

// Skipjack
// The key argument should be 10 bytes.
func (this Cryptobin) Skipjack() Cryptobin {
    this.multiple = Skipjack

    return this
}

// Serpent
// The key argument should be 16, 24, 32 bytes.
func (this Cryptobin) Serpent() Cryptobin {
    this.multiple = Serpent

    return this
}

// Loki97
// The key argument should be 16, 24, 32 bytes.
func (this Cryptobin) Loki97() Cryptobin {
    this.multiple = Loki97

    return this
}

// Saferplus
// The key argument should be 8, 16 bytes.
func (this Cryptobin) Saferplus() Cryptobin {
    this.multiple = Saferplus

    return this
}

// Mars
// The key argument should be 16, 24, 32 bytes.
func (this Cryptobin) Mars() Cryptobin {
    this.multiple = Mars

    return this
}

// Mars2
// The key argument should be from 128 to 448 bits
func (this Cryptobin) Mars2() Cryptobin {
    this.multiple = Mars2

    return this
}

// Wake
// The key argument should be 16 bytes.
func (this Cryptobin) Wake() Cryptobin {
    this.multiple = Wake

    return this
}

// Enigma
// The key argument should be 13 bytes.
func (this Cryptobin) Enigma() Cryptobin {
    this.multiple = Enigma

    return this
}

// Hight
// The key argument should be 16 bytes.
func (this Cryptobin) Hight() Cryptobin {
    this.multiple = Hight

    return this
}

// Lea
// The key argument should be 16, 24, 32 bytes.
func (this Cryptobin) Lea() Cryptobin {
    this.multiple = Lea

    return this
}

// Panama
// The key argument should be 32 bytes.
func (this Cryptobin) Panama() Cryptobin {
    this.multiple = Panama

    return this
}

// Square
// The key argument should be 32 bytes.
func (this Cryptobin) Square() Cryptobin {
    this.multiple = Square

    return this
}

// Magenta
// The key argument should be 16, 24, 32 bytes.
func (this Cryptobin) Magenta() Cryptobin {
    this.multiple = Magenta

    return this
}

// Kasumi
// The key argument should be 16 bytes.
func (this Cryptobin) Kasumi() Cryptobin {
    this.multiple = Kasumi

    return this
}

// E2
// The key argument should be 16, 24, 32 bytes.
func (this Cryptobin) E2() Cryptobin {
    this.multiple = E2

    return this
}

// Crypton1
// The key argument should be 16, 24, 32 bytes.
func (this Cryptobin) Crypton1() Cryptobin {
    this.multiple = Crypton1

    return this
}

// Clefia
// The key argument should be 16, 24, 32 bytes.
func (this Cryptobin) Clefia() Cryptobin {
    this.multiple = Clefia

    return this
}

// Safer
// The key argument should be 16, 24, 32 bytes.
func (this Cryptobin) Safer(typ string, rounds int32) Cryptobin {
    this.multiple = Safer

    if typ == "K" || typ == "SK" {
        this.config.Set("type", typ)
    }

    this.config.Set("rounds", rounds)

    return this
}

// Noekeon
// The key argument should be 16 bytes.
func (this Cryptobin) Noekeon() Cryptobin {
    this.multiple = Noekeon

    return this
}

// Multi2
// The key argument should be 40 bytes.
func (this Cryptobin) Multi2(rounds int32) Cryptobin {
    this.multiple = Multi2

    this.config.Set("rounds", rounds)

    return this
}

// Kseed
// The key argument should be 16 bytes.
func (this Cryptobin) Kseed() Cryptobin {
    this.multiple = Kseed

    return this
}

// Khazad
// The key argument should be 16 bytes.
func (this Cryptobin) Khazad() Cryptobin {
    this.multiple = Khazad

    return this
}

// Anubis
// The key argument should be 16, 20, 24, 28, 32, 36, and 40.
func (this Cryptobin) Anubis() Cryptobin {
    this.multiple = Anubis

    return this
}

// Present
// The key argument should be 10 or 16 bytes.
func (this Cryptobin) Present() Cryptobin {
    this.multiple = Present

    return this
}

// Trivium
// The key argument should be 10 bytes.
func (this Cryptobin) Trivium() Cryptobin {
    this.multiple = Trivium

    return this
}

// 使用类型
func (this Cryptobin) MultipleBy(multiple Multiple, cfg ...map[string]any) Cryptobin {
    this.multiple = multiple

    for _, v := range cfg {
        for kk, vv := range v {
            this.config.Set(kk, vv)
        }
    }

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

// 填充密码块链接模式
func (this Cryptobin) PCBC() Cryptobin {
    this.mode = PCBC

    return this
}

// 密码反馈模式
func (this Cryptobin) CFB() Cryptobin {
    this.mode = CFB

    return this
}

// 密码反馈模式
func (this Cryptobin) CFB1() Cryptobin {
    this.mode = CFB1

    return this
}

// 密码反馈模式, 8字节
func (this Cryptobin) CFB8() Cryptobin {
    this.mode = CFB8

    return this
}

// 密码反馈模式
func (this Cryptobin) CFB16() Cryptobin {
    this.mode = CFB16

    return this
}

// 密码反馈模式
func (this Cryptobin) CFB32() Cryptobin {
    this.mode = CFB32

    return this
}

// 密码反馈模式
func (this Cryptobin) CFB64() Cryptobin {
    this.mode = CFB64

    return this
}

// 密码反馈模式, 标准库 CFB 别名
func (this Cryptobin) CFB128() Cryptobin {
    this.mode = CFB128

    return this
}

// OpenPGP 反馈模式
func (this Cryptobin) OCFB(resync bool) Cryptobin {
    this.mode = OCFB

    this.config.Set("resync", resync)

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

// OCB
// OCB nounce size, should be in [0, cipher.block.BlockSize]
func (this Cryptobin) OCB(nonce string, additional ...string) Cryptobin {
    this.mode = OCB

    this.config.Set("nonce", []byte(nonce))

    if len(additional) > 0 {
        this.config.Set("additional", []byte(additional[0]))
    }

    return this
}

// EAX
// EAX nounce size, should be in > 0
func (this Cryptobin) EAX(nonce string, additional ...string) Cryptobin {
    this.mode = EAX

    this.config.Set("nonce", []byte(nonce))

    if len(additional) > 0 {
        this.config.Set("additional", []byte(additional[0]))
    }

    return this
}

// NCFB
func (this Cryptobin) NCFB() Cryptobin {
    this.mode = NCFB

    return this
}

// NOFB
func (this Cryptobin) NOFB() Cryptobin {
    this.mode = NOFB

    return this
}

// BC
func (this Cryptobin) BC() Cryptobin {
    this.mode = BC

    return this
}

// HCTR
func (this Cryptobin) HCTR(tweak, hkey []byte) Cryptobin {
    this.mode = HCTR

    this.config.Set("tweak", tweak)
    this.config.Set("hkey", hkey)

    return this
}

// 使用模式
func (this Cryptobin) ModeBy(mode Mode, cfg ...map[string]any) Cryptobin {
    this.mode = mode

    for _, v := range cfg {
        for kk, vv := range v {
            this.config.Set(kk, vv)
        }
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

// PBOC2 补码
func (this Cryptobin) PBOC2Padding() Cryptobin {
    this.padding = PBOC2Padding

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

// 使用补码算法
func (this Cryptobin) PaddingBy(padding Padding, cfg ...map[string]any) Cryptobin {
    this.padding = padding

    for _, v := range cfg {
        for kk, vv := range v {
            this.config.Set(kk, vv)
        }
    }

    return this
}

// ==========

// 不做处理
func (this Cryptobin) NoParse() Cryptobin {
    this.parsedData = this.data

    return this
}
