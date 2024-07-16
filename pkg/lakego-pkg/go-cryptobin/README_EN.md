## go-cryptobin

go-cryptobin is a go encrypt or decrypt library

[中文](README.md) | English


### Desc

*  go-cryptobin library has encrypt / decrypt or sign / verify
*  sym encrypts（Aes/Des/TripleDes/SM4/Tea/Twofish/Xts）
*  encrypt mode（ECB/CBC/PCBC/CFB/NCFB/OFB/NOFB/CTR/GCM/CCM）
*  encrypt padding（NoPadding/ZeroPadding/PKCS5Padding/PKCS7Padding/X923Padding/ISO10126Padding/ISO97971Padding/ISO7816_4Padding/PBOC2Padding/TBCPadding/PKCS1Padding）
*  asym encrypts（Aes（RSA/SM2/EIGamal）
*  asym sign（RSA/RSA-PSS/DSA/ECDSA/EdDSA/SM2/EIGamal/ED448/Gost）
*  default setting `Aes`, `ECB`, `NoPadding`


### Env

 - Go >= 1.20


### Download

~~~go
go get -u github.com/deatil/go-cryptobin
~~~


### Get Starting

~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func main() {
    // encrypt
    cypten := crypto.
        FromString("useData").
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CBC().
        PKCS7Padding().
        Encrypt().
        ToBase64String()

    // decrypt
    cyptde := crypto.
        FromBase64String("i3FhtTp5v6aPJx0wTbarwg==").
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CBC().
        PKCS7Padding().
        Decrypt().
        ToString()

    // i3FhtTp5v6aPJx0wTbarwg==
    fmt.Println("encrypt res：", cypt)
    fmt.Println("decrypt res：", cyptde)
}

~~~


### Struct Desc

*  default setting `Aes`, `ECB`, `NoPadding`. default not use padding, input need n*16 length, not right length need other padding
~~~go
// encrypt data
cypt := crypto.
    FromString("useData5useData5").
    SetKey("dfertf12dfertf12").
    Encrypt().
    ToBase64String()
// decrypt data
cyptde := crypto.
    FromBase64String("eZf7c3fcwKlmrqogiEHbJg==").
    SetKey("dfertf12dfertf12").
    Decrypt().
    ToString()
~~~

*  Use Desc
~~~go
// Code
// Tips: SetKey,SetIv,Encrypt Type,Mode,Padding at `Action Type` before can move sorts
ret := crypto.
    FromString("string"). // Data Src
    SetKey("key_string"). // Set Key
    SetIv("iv_string").   // Set Iv
    Aes().                // Encrypt Type
    CBC().                // Mode
    PKCS7Padding().       // Padding
    Encrypt().            // Action Type
    ToBase64String()      // To Data Type
~~~


### PKG Funcs

*  Data From:
`FromBytes(data []byte)`, `FromString(data string)`, `FromBase64String(data string)`, `FromHexString(data string)`
*  Set Key:
`SetKey(data string)`, `WithKey(key []byte)`
*  Set IV:
`SetIv(data string)`, `WithIv(iv []byte)`
*  Encrypt Type:
`Aes()`, `Des()`, `TripleDes()`, `Twofish()`, `Blowfish()`, `Tea(rounds ...int)`, `Xtea()`, `Cast5()`, `RC4()`, `Idea()`, `SM4()`, `Chacha20(counter ...uint32)`, `Chacha20poly1305(additional ...[]byte)`, `Xts(cipher string, sectorNum uint64)`
*  Encrypt Mode:
`ECB()`, `CBC()`, `PCBC()`, `CFB()`, `OFB()`, `CTR()`, `GCM(additional ...[]byte)`, `CCM(additional ...[]byte)`
*  Paddings:
`NoPadding()`, `ZeroPadding()`, `PKCS5Padding()`, `PKCS7Padding()`, `X923Padding()`, `ISO10126Padding()`, `ISO7816_4Padding()`,`ISO97971Padding()`,`PBOC2Padding()`, `TBCPadding()`, `PKCS1Padding(bt ...string)`
*  Action Type:
`Encrypt()`, `Decrypt()`, `FuncEncrypt(f func(Cryptobin) Cryptobin)`, `FuncDecrypt(f func(Cryptobin) Cryptobin)`
*  To Data Type:
`ToBytes()`, `ToString()`, `ToBase64String()`, `ToHexString()`

*  more data [docs](docs/README.md)


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
