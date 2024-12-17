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
func (this Cryptobin) Chacha20(counter ...uint32) Cryptobin {
    this.multiple = Chacha20

    if len(counter) > 0 {
        this.config.Set("counter", counter[0])
    }

    return this
}

// Chacha20poly1305
// nonce is 12 bytes
func (this Cryptobin) Chacha20poly1305(additional ...[]byte) Cryptobin {
    this.multiple = Chacha20poly1305

    if len(additional) > 0 {
        this.config.Set("additional", additional[0])
    }

    return this
}

// Chacha20poly1305X
// nonce is 24 bytes
func (this Cryptobin) Chacha20poly1305X(additional ...[]byte) Cryptobin {
    this.multiple = Chacha20poly1305X

    if len(additional) > 0 {
        this.config.Set("additional", additional[0])
    }

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
// sbox is [SboxDESDerivedParamSet | SboxRFC4357TestParamSet | SboxGostR341194CryptoProParamSet | SboxTC26gost28147paramZ | SboxEACParamSet]
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

// Serpent
// The key argument should be 16, 24, 32 bytes.
func (this Cryptobin) Serpent() Cryptobin {
    this.multiple = Serpent

    return this
}

// Saferplus
// The key argument should be 8, 16 bytes.
func (this Cryptobin) Saferplus() Cryptobin {
    this.multiple = Saferplus

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

// Kasumi
// The key argument should be 16 bytes.
func (this Cryptobin) Kasumi() Cryptobin {
    this.multiple = Kasumi

    return this
}

// Safer
// The typ should be K, SK string.
// The key argument should be 16, 24, 32 bytes.
func (this Cryptobin) Safer(typ string, rounds int32) Cryptobin {
    this.multiple = Safer

    if typ == "K" || typ == "SK" {
        this.config.Set("type", typ)
    }

    this.config.Set("rounds", rounds)

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

// Rijndael
// The blockSize argument should be 16, 20, 24, 28 or 32 bytes.
// The key argument should be 16, 24 or 32 bytes.
func (this Cryptobin) Rijndael(blockSize int) Cryptobin {
    this.multiple = Rijndael

    this.config.Set("block_size", blockSize)

    return this
}

// Rijndael128
// The key argument should be 16, 24 or 32 bytes.
func (this Cryptobin) Rijndael128() Cryptobin {
    this.multiple = Rijndael128

    return this
}

// Rijndael192
// The key argument should be 16, 24 or 32 bytes.
func (this Cryptobin) Rijndael192() Cryptobin {
    this.multiple = Rijndael192

    return this
}

// Rijndael256
// The key argument should be 16, 24 or 32 bytes.
func (this Cryptobin) Rijndael256() Cryptobin {
    this.multiple = Rijndael256

    return this
}

// Twine
// The key argument should be 10 or 16 bytes.
func (this Cryptobin) Twine() Cryptobin {
    this.multiple = Twine

    return this
}

// Misty1
// The key argument should be 16 bytes.
func (this Cryptobin) Misty1() Cryptobin {
    this.multiple = Misty1

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
// ECB mode
func (this Cryptobin) ECB() Cryptobin {
    this.mode = ECB

    return this
}

// 密码分组链接模式
// CBC mode
func (this Cryptobin) CBC() Cryptobin {
    this.mode = CBC

    return this
}

// 填充密码块链接模式
// PCBC mode
func (this Cryptobin) PCBC() Cryptobin {
    this.mode = PCBC

    return this
}

// 密码反馈模式
// CFB mode
func (this Cryptobin) CFB() Cryptobin {
    this.mode = CFB

    return this
}

// 密码反馈模式, 1字节
// CFB1 mode
func (this Cryptobin) CFB1() Cryptobin {
    this.mode = CFB1

    return this
}

// 密码反馈模式, 8字节
// CFB8 mode
func (this Cryptobin) CFB8() Cryptobin {
    this.mode = CFB8

    return this
}

// 密码反馈模式, 标准库 CFB 别名
// CFB128 mode
func (this Cryptobin) CFB128() Cryptobin {
    this.mode = CFB128

    return this
}

// OpenPGP 反馈模式
// OCFB mode
func (this Cryptobin) OCFB(resync bool) Cryptobin {
    this.mode = OCFB

    this.config.Set("resync", resync)

    return this
}

// 输出反馈模式
// OFB mode
func (this Cryptobin) OFB() Cryptobin {
    this.mode = OFB

    return this
}

// 输出反馈模式, 8字节
// OFB8 mode
func (this Cryptobin) OFB8() Cryptobin {
    this.mode = OFB8

    return this
}

// 计算器模式
// CTR mode
func (this Cryptobin) CTR() Cryptobin {
    this.mode = CTR

    return this
}

// GCM
func (this Cryptobin) GCM(additional ...[]byte) Cryptobin {
    this.mode = GCM

    this.config.Set("tag_size", 0)

    if len(additional) > 0 {
        this.config.Set("additional", additional[0])
    }

    return this
}

// GCMWithTagSize
func (this Cryptobin) GCMWithTagSize(tagSize int, additional ...[]byte) Cryptobin {
    this.mode = GCM

    this.config.Set("tag_size", tagSize)

    if len(additional) > 0 {
        this.config.Set("additional", additional[0])
    }

    return this
}

// CCM
// ccm nounce size, should be in [7,13]
func (this Cryptobin) CCM(additional ...[]byte) Cryptobin {
    this.mode = CCM

    this.config.Set("tag_size", 0)

    if len(additional) > 0 {
        this.config.Set("additional", additional[0])
    }

    return this
}

// CCMWithTagSize
// ccm nounce size, should be in [7,13]
func (this Cryptobin) CCMWithTagSize(tagSize int, additional ...[]byte) Cryptobin {
    this.mode = CCM

    this.config.Set("tag_size", tagSize)

    if len(additional) > 0 {
        this.config.Set("additional", additional[0])
    }

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
// use Mode By mode enum
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
// NoPadding
func (this Cryptobin) NoPadding() Cryptobin {
    this.padding = NoPadding

    return this
}

// Zero 补码
// ZeroPadding
func (this Cryptobin) ZeroPadding() Cryptobin {
    this.padding = ZeroPadding

    return this
}

// PKCS5 补码
// PKCS5Padding
func (this Cryptobin) PKCS5Padding() Cryptobin {
    this.padding = PKCS5Padding

    return this
}

// PKCS7 补码
// PKCS7Padding
func (this Cryptobin) PKCS7Padding() Cryptobin {
    this.padding = PKCS7Padding

    return this
}

// X923 补码
// X923Padding
func (this Cryptobin) X923Padding() Cryptobin {
    this.padding = X923Padding

    return this
}

// ISO10126 补码
// ISO10126Padding
func (this Cryptobin) ISO10126Padding() Cryptobin {
    this.padding = ISO10126Padding

    return this
}

// ISO7816_4 补码
// ISO7816_4Padding
func (this Cryptobin) ISO7816_4Padding() Cryptobin {
    this.padding = ISO7816_4Padding

    return this
}

// ISO97971 补码
// ISO97971Padding
func (this Cryptobin) ISO97971Padding() Cryptobin {
    this.padding = ISO97971Padding

    return this
}

// PBOC2 补码
// PBOC2Padding
func (this Cryptobin) PBOC2Padding() Cryptobin {
    this.padding = PBOC2Padding

    return this
}

// TBC 补码
// TBCPadding
func (this Cryptobin) TBCPadding() Cryptobin {
    this.padding = TBCPadding

    return this
}

// 使用补码算法
// use Padding by padding enum
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
// No Parse action to change data
func (this Cryptobin) NoParse() Cryptobin {
    this.parsedData = this.data

    return this
}
