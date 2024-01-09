### 使用方法

* 对称加密的 `key` 和输入输出数据通常都为大端数据(BigEndian)。
* 本库对称加密数据以标准数据类型为依据，不提供大端小端的不同输入和输出。
* 通俗的说就是只实现了对称加密文档提供的标准数据类型的输入和输出，不做额外的数据类型转换。


### 开始使用

~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func main() {
    // 加密
    cypt := crypto.
        FromString("useData").
        SetKey("dfertf12dfertf12").
        Aes().
        ECB().
        PKCS7Padding().
        Encrypt().
        ToBase64String()

    // 解密
    cyptde := crypto.
        FromBase64String("i3FhtTp5v6aPJx0wTbarwg==").
        SetKey("dfertf12dfertf12").
        Aes().
        ECB().
        PKCS7Padding().
        Decrypt().
        ToString()

    // i3FhtTp5v6aPJx0wTbarwg==
    fmt.Println("加密结果：", cypt)
    fmt.Println("解密结果：", cyptde)
}

~~~


### 结构说明

*  默认方式 `Aes`, `ECB`, `NoPadding`
~~~go
// 加密数据
cypt := crypto.
    FromString("useData").
    SetKey("dfertf12dfertf12").
    Encrypt().
    ToBase64String()
// 解密数据
cyptde := crypto.
    FromBase64String("i3FhtTp5v6aPJx0wTbarwg==").
    SetKey("dfertf12dfertf12").
    Decrypt().
    ToString()
~~~

*  完整方式
~~~go
// 注意: 设置密码,加密类型,加密模式,补码方式 在 操作类型 之前, 可以调换顺序
var ret string = crypto.
    FromString("string"). // 数据来源, 待加密数据/待解密数据
    SetKey("key").        // 设置密码
    SetIv("iv_string").   // 设置向量
    Aes().                // 加密类型
    CBC().                // 加密模式
    PKCS7Padding().       // 补码方式
    Encrypt().            // 操作类型, 加密或者解密
    ToBase64String()      // 返回结果数据类型
~~~


### 可用方法

*  数据来源:
`FromBytes(data []byte)`, `FromString(data string)`, `FromBase64String(data string)`, `FromHexString(data string)`
*  设置密码:
`SetKey(data string)`, `WithKey(key []byte)`
*  设置向量:
`SetIv(data string)`, `WithIv(iv []byte)`
*  加密类型:
`Aes()`, `Des()`, `TripleDes()`, `Twofish()`, `Blowfish()`, `Tea(rounds ...int)`, `Xtea()`, `Cast5()`, `RC4()`, `Idea()`, `SM4()`, `Chacha20(nonce string, counter ...uint32)`, `Chacha20poly1305(nonce string, additional string)`, `Xts(cipher string, sectorNum uint64)`
*  加密模式:
`ECB()`, `CBC()`, `PCBC()`, `CFB()`, `OFB()`, `CTR()`, `GCM(nonce string, additional ...string)`, `CCM(nonce string, additional ...string)`
*  补码方式:
`NoPadding()`, `ZeroPadding()`, `PKCS5Padding()`, `PKCS7Padding()`, `X923Padding()`, `ISO10126Padding()`, `ISO7816_4Padding()`,`ISO97971Padding()`,`PBOC2Padding()`, `TBCPadding()`, `PKCS1Padding(bt ...string)`
*  操作类型:
`Encrypt()`, `Decrypt()`, `FuncEncrypt(f func(Cryptobin) Cryptobin)`, `FuncDecrypt(f func(Cryptobin) Cryptobin)`
*  返回数据类型:
`ToBytes()`, `ToString()`, `ToBase64String()`, `ToHexString()`


### IV 向量

`ECB()` 模式不需要设置 `IV` 向量，其他的已知模式都需要设置 `IV` 向量


### 支持的加密类型, 加密模式及补码方式

支持的加密类型
~~~go
Aes
Des
TwoDes
TripleDes
Twofish
Blowfish
Tea(rounds ...int)
Xtea
Cast5
Cast256
RC2
RC4
RC4MD5
RC5
RC6
Idea
SM4
Chacha20(nonce string, counter ...uint32)
Chacha20poly1305(nonce string, additional string)
Chacha20poly1305X(nonce string, additional string)
Xts(cipher string, sectorNum uint64)
Salsa20(nonce string)
Seed
Aria
Camellia
Gost(sbox any)
Kuznyechik
Skipjack
Serpent
Loki97
Saferplus
Mars
Mars2
Wake
Enigma
Hight
Lea
Panama
Square
Magenta
Kasumi
E2
Crypton1
Clefia
Safer(typ string, rounds int32)
Noekeon
Multi2(rounds int32)
Kseed
Khazad
Anubis
Present
Trivium
Rijndael(blockSize int)
Rijndael128
Rijndael192
Rijndael256
~~~

支持的加密模式
~~~go
ECB
CBC
PCBC
CFB
CFB1
CFB8
CFB16
CFB32
CFB64
CFB128
OCFB(resync bool)
OFB
OFB8
NCFB
NOFB
CTR
GCM(nonce string, additional ...string)
CCM(nonce string, additional ...string)
OCB(nonce string, additional ...string)
EAX(nonce string, additional ...string)
BC
HCTR(tweak, hkey []byte)
~~~

支持的补码方式
~~~go
NoPadding
ZeroPadding
PKCS5Padding
PKCS7Padding
X923Padding
ISO10126Padding
ISO7816_4Padding
ISO97971Padding
PBOC2Padding
TBCPadding
PKCS1Padding(bt ...string)
~~~

