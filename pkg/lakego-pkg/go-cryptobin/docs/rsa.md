### Rsa 使用说明

* 使用
~~~go
package main

import (
    "fmt"

    cryptobin "github.com/deatil/go-cryptobin/cryptobin/rsa"
    "github.com/deatil/lakego-filesystem/filesystem"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 生成证书
    // bits = 512 | 1024 | 2048 | 4096
    obj := cryptobin.
        NewRsa().
        GenerateKey(2048)

    objPriKey := obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        // CreatePKCS1PrivateKey().
        // CreatePKCS1PrivateKeyWithPassword("123", "AES256CBC").
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256").
        ToKeyString()
    objPubKey := obj.
        CreatePKCS1PublicKey().
        // CreatePKCS8PublicKey().
        ToKeyString()
    fs.Put("./runtime/key/rsa", objPriKey)
    fs.Put("./runtime/key/rsa.pub", objPubKey)

    // 验证
    obj2 := cryptobin.NewRsa()

    obj2Pri, _ := fs.Get("./runtime/key/rsa")
    obj2cypt := obj2.
        FromString("test-pass").
        FromPrivateKey([]byte(obj2Pri)).
        // FromPrivateKeyWithPassword([]byte(obj2Pri), "123").
        // FromPKCS1PrivateKey([]byte(obj2Pri)).
        // FromPKCS1PrivateKeyWithPassword([]byte(obj2Pri), "123").
        // FromPKCS8PrivateKey([]byte(obj2Pri)).
        // FromPKCS8PrivateKeyWithPassword([]byte(obj2Pri), "123").
        Sign().
        // PSSSign().
        ToBase64String()
    obj2Pub, _ := fs.Get("./runtime/key/rsa.pub")
    obj2cyptde := obj2.
        FromBase64String("MjkzNzYzMDE1NjgzNDExMTM0ODE1MzgxOTAxMDIxNzQ0Nzg3NTc3NTAxNTU2MDIwNzg4OTc1MzY4Mzc0OTE5NzcyOTg3NjI1MTc2OTErNDgzNDU3NDAyMzYyODAzMDM3MzE1NjE1NDk1NDEzOTQ4MDQ3NDQ3ODA0MDE4NDY5NDA1OTA3ODExNjM1Mzk3MDEzOTY4MTM5NDg2NDc=").
        // FromPublicKey([]byte(obj2Pub)).
        // FromPKCS1PublicKey([]byte(obj2Pub)).
        FromPKCS8PublicKey([]byte(obj2Pub)).
        Verify([]byte("test-pass")).
        // PSSVerify([]byte("测试")).
        ToVerify()

    // =====

    // 生成证书
    obj := cryptobin_rsa.New().GenerateKey(2048)

    objPriKey := obj.
        CreatePKCS8PrivateKeyWithPassword("123", cryptobin_rsa.Opts{
            Cipher:  cryptobin_rsa.GetCipherFromName("AES256CBC"),
            KDFOpts: cryptobin_rsa.ScryptOpts{
                CostParameter:            1 << 15,
                BlockSize:                8,
                ParallelizationParameter: 1,
                SaltSize:                 8,
            },
        }).
        ToKeyString()
    objPubKey := obj.
        CreatePKCS1PublicKey().
        // CreatePKCS8PublicKey().
        ToKeyString()
    fs.Put("./runtime/key/rsa_pkcs8_en11", objPriKey)
    fs.Put("./runtime/key/rsa_pkcs8_en11.pub", objPubKey)

    // =====

    // Rsa 加密解密 - 公钥加密/私钥解密
    rsa := cryptobin.NewRsa()

    enkey, _ := fs.Get("./runtime/key/rsa_key.pub")
    cypt := rsa.
        FromString("test-pass").
        // FromPublicKey([]byte(enkey)).
        // FromPKCS1PublicKey([]byte(enkey)).
        FromPKCS8PublicKey([]byte(enkey)).
        Encrypt().
        // EncryptOAEP("SHA1")
        ToBase64String()
    dekey, _ := fs.Get("./runtime/key/rsa_key")
    cyptde := rsa.
        FromBase64String("MHECIFVKOBAB9uiXrFQlNexfJuv7tjuydu7UdMYpTxQ/mPeHAiBSZdqNaciEP3XgX8xT2JLap4dWedX1EDQh7JyqifhHQAQgPcr5+KHIz3v300sGPc7nv6VM9fOo/kgPTHqZy5MtXMMECVKFT0dwWJwdCQ==").
        FromPrivateKey([]byte(dekey)).
        Decrypt().
        // DecryptOAEP("SHA1")
        ToString()

    // =====

    // RSA 加密测试2
    rsaPfx := encoding.Base64Decode("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")
    rsa2 := cryptobin.NewRsa().FromPKCS12CertWithPassword([]byte(rsaPfx), "")

    var rsa2Err []error
    rsa2cypt := rsa2.
        OnError(func(errs []error) {
            rsa2Err = errs
        }).
        MakePublicKey().
        FromString("test-pass").
        Encrypt().
        ToBase64String()
    rsa2cyptde := rsa2.
        FromBase64String("VucMmjS1QrQuIqK6tbI1R5MPzb/VFg31RYxG/rGUxhlp1NAqgOpbb/sAusToLeKWpAU/08qWmp+6K3iW7fEKxM4oTFIc9jrQ/Su6ywB3JLRNoh1/m0I8BNSaKee0vKL4wPheOiDykNt3Wiqe14sWmwu8LLJHWCk2H7IiWr7TySUKnhYrlmEyNnGH/yFg17wXSKhqUU/mQ75OOU8uk4G6ZLBX68FiXfsHWkEAYz/fKmf9tJKyAMwHgL0OpUPmdH97AgG9nghA3EeLhwe2F3XwYWBc0MMCVxNlziBrcF/hnRxfQ98jiv66M680K0SIwiLC3Y/Gd/BGKS4VEEL8U+Gu/Q==").
        Decrypt().
        ToString()

    // =====

    // Rsa 加密解密 - 私钥加密/公钥解密
    rsa := cryptobin.NewRsa()

    enkey, _ := fs.Get("./runtime/key/rsa_key")
    cypt := rsa.
        FromString("test-pass").
        FromPrivateKey([]byte(enkey)).
        PriKeyEncrypt().
        ToBase64String()
    dekey, _ := fs.Get("./runtime/key/rsa_key.pub")
    cyptde := rsa.
        FromBase64String("MHECIFVKOBAB9uiXrFQlNexfJuv7tjuydu7UdMYpTxQ/mPeHAiBSZdqNaciEP3XgX8xT2JLap4dWedX1EDQh7JyqifhHQAQgPcr5+KHIz3v300sGPc7nv6VM9fOo/kgPTHqZy5MtXMMECVKFT0dwWJwdCQ==").
        // FromPublicKey([]byte(dekey)).
        // FromPKCS1PublicKey([]byte(dekey)).
        FromPKCS8PublicKey([]byte(dekey)).
        PubKeyDecrypt().
        ToString()

    // =====

    // Rsa 生成证书2
    rsa22 := cryptobin.NewRsa().GenerateKey(2048)
    rsaPriKey22 := rsa22.
        CreatePKCS1PrivateKey().
        ToKeyString()
    rsaPubKey22 := rsa22.
        CreatePKCS1PublicKey().
        ToKeyString()

    // =====

    // PSS 验证
    pri, _ := fs.Get("./runtime/key/sample_key")
    pub, _ := fs.Get("./runtime/key/sample_key.pub")
    rsa := cryptobin.NewRsa()
    rsaPriKey := rsa.
        FromPrivateKey([]byte(pri)).
        FromString("测试").
        WithSignHash("SHA256").
        PSSSign().
        ToBase64String()
    rsaPubKey := rsa.
        FromBase64String(rsaPriKey).
        FromPublicKey([]byte(pub)).
        WithSignHash("SHA256").
        PSSVerify([]byte("测试")).
        ToVerify()

    // =====

    // 检测私钥公钥是否匹配
    pri, _ := fs.Get(prifile)
    pub, _ := fs.Get(pubfile)

    res := cryptobin_rsa.New().
        FromPKCS8PrivateKey([]byte(pri)).
        FromPKCS8PublicKey([]byte(pub)).
        // FromPrivateKey([]byte(obj2Pri)).
        // FromPrivateKeyWithPassword([]byte(obj2Pri), "123").
        // FromPKCS1PrivateKey([]byte(obj2Pri)).
        // FromPKCS1PrivateKeyWithPassword([]byte(obj2Pri), "123").
        // FromPKCS8PrivateKey([]byte(obj2Pri)).
        // FromPKCS8PrivateKeyWithPassword([]byte(obj2Pri), "123").
        // FromPublicKey([]byte(dekey)).
        // FromPKCS1PublicKey([]byte(dekey)).
        // FromPKCS8PublicKey([]byte(dekey)).
        CheckKeyPair()

    fmt.Printf("check res: %#v", res)

}
~~~
