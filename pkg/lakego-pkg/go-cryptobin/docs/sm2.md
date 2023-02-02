### SM2 使用说明

* 使用
~~~go
package main

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
    cryptobin_sm2 "github.com/deatil/go-cryptobin/cryptobin/sm2"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 生成证书
    obj := cryptobin_sm2.
        NewSM2().
        GenerateKey()

    objPriKey := obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123").
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        ToKeyString()
    objPubKey := obj.
        CreatePublicKey().
        ToKeyString()
    fs.Put("./runtime/key/sm2", objPriKey)
    fs.Put("./runtime/key/sm2.pub", objPubKey)

    // 验证
    obj2 := cryptobin.NewSM2()

    obj2Pri, _ := fs.Get("./runtime/key/sm2")
    obj2cypt := obj2.
        FromString("test-pass").
        FromPrivateKey([]byte(obj2Pri)).
        // FromPrivateKeyWithPassword([]byte(obj2Pri), "123").
        Sign().
        ToBase64String()
    obj2Pub, _ := fs.Get("./runtime/key/sm2.pub")
    obj2cyptde := obj2.
        FromBase64String("MjkzNzYzMDE1NjgzNDExMTM0ODE1MzgxOTAxMDIxNzQ0Nzg3NTc3NTAxNTU2MDIwNzg4OTc1MzY4Mzc0OTE5NzcyOTg3NjI1MTc2OTErNDgzNDU3NDAyMzYyODAzMDM3MzE1NjE1NDk1NDEzOTQ4MDQ3NDQ3ODA0MDE4NDY5NDA1OTA3ODExNjM1Mzk3MDEzOTY4MTM5NDg2NDc=").
        FromPublicKey([]byte(obj2Pub)).
        Verify([]byte("test-pass")).
        ToVerify()

    // =====

    // SM2 加密
    sm2 := cryptobin_sm2.NewSM2()

    enkey2, _ := fs.Get("./runtime/key/sm2_en_key.pub")
    sm2cypt := sm2.
        FromString("test-pass").
        FromPublicKey([]byte(enkey2)).
        Encrypt().
        ToBase64String()
    dekey2, _ := fs.Get("./runtime/key/sm2_en_key")
    sm2cyptde := sm2.
        FromBase64String("MHECIBcuicIhrELarhD9IqQiJLRejx6R/ywwDlspYneUwF12AiAd8HNw///hnFQDBzFeYj3XzQdF792vcNhEsJ2bothR5wQgfFWNiPVht0Fv+DBPaxm5jMV2XKvQE7sNVkX1T7ep+cEECSnzLy6t5NtHOg==").
        FromPrivateKeyWithPassword([]byte(dekey2), "123").
        Decrypt().
        ToString()

    // =====

    // SM2 加密2
    sm2 := cryptobin_sm2.NewSM2()

    enkey2, _ := fs.Get("./runtime/key/sm2_key.pub")
    sm2cypt := sm2.
        FromString("test-pass").
        FromPublicKey([]byte(enkey2)).
        SetMode("C1C3C2"). // C1C3C2 | C1C2C3
        Encrypt().
        ToBase64String()
    dekey2, _ := fs.Get("./runtime/key/sm2_key")
    sm2cyptde := sm2.
        FromBase64String("MHECIFVKOBAB9uiXrFQlNexfJuv7tjuydu7UdMYpTxQ/mPeHAiBSZdqNaciEP3XgX8xT2JLap4dWedX1EDQh7JyqifhHQAQgPcr5+KHIz3v300sGPc7nv6VM9fOo/kgPTHqZy5MtXMMECVKFT0dwWJwdCQ==").
        FromPrivateKey([]byte(dekey2)).
        SetMode("C1C3C2"). // C1C3C2 | C1C2C3
        Decrypt().
        ToString()

    // =====

    // SM2 验证
    sm2 := cryptobin_sm2.NewSM2()

    enkey2, _ := fs.Get("./runtime/key/sm2_key")
    sm2cypt := sm2.
        FromString("test-pass").
        FromPrivateKey([]byte(enkey2)).
        Sign().
        ToBase64String()
    dekey2, _ := fs.Get("./runtime/key/sm2_key.pub")
    sm2cyptde := sm2.
        FromBase64String("MEUCIDztMEbHBdSeU2xxM93nsluloXB06k8Tt62hW+3t1vOHAiEA8r+9O0zIe5hpB7MmT7NCw/bhwVJbBh6hNtgjSFilzrU=").
        FromPublicKey([]byte(dekey2)).
        Verify([]byte("test-pass")).
        ToVerify()

    // =====

    // SM2 验证2
    sm2 := cryptobin_sm2.NewSM2()

    enkey2, _ := fs.Get("./runtime/key/sm2_en_key")
    sm2cypt := sm2.
        FromString("test-pass").
        FromPrivateKeyWithPassword([]byte(enkey2), "123").
        Sign().
        ToBase64String()
    dekey2, _ := fs.Get("./runtime/key/sm2_en_key.pub")
    sm2cyptde := sm2.
        FromBase64String("MEQCIE4DzLVkR9W+zQfXiwfwcOe/mk6PUNHBrSJIRdHT7diaAiAHaNNSxgwVLkZzXoHV4Tgqsim7c4ZwaPF+mca4mFZxLw==").
        FromPublicKey([]byte(dekey2)).
        Verify([]byte("test-pass")).
        ToVerify()

    // =====

    // SM2 生成 x,y,d 16进制
    sm2 := cryptobin_sm2.NewSM2()

    dekey2, _ := fs.Get("./runtime/key/sm2_key")
    x := sm2.
        FromPrivateKey([]byte(dekey2)).
        GetPrivateKeyXHexString()
    y := sm2.
        FromPrivateKey([]byte(dekey2)).
        GetPrivateKeyYHexString()
    d := sm2.
        FromPrivateKey([]byte(dekey2)).
        GetPrivateKeyDHexString()

    // =====

    // SM2 加密2
    sm2PublicKeyX  := "a4b75c4c8c44d11687bdd93c0883e630c895234beb685910efbe27009ad911fa"
    sm2PublicKeyY  := "d521f5e8249de7a405f254a9888cbb8e651fd60c50bd22bd182a4bc7d1261c94"
    sm2PrivateKeyD := "0f495b5445eb59ddecf0626f5ca0041c550584f0189e89d95f8d4c52499ff838"

    sm2 := cryptobin_sm2.NewSM2()
    sm2PriKey := sm2.
        FromPublicKeyXYString(sm2PublicKeyX, sm2PublicKeyY).
        CreatePublicKey().
        ToKeyString()
    sm2PubKey := sm2.
        FromPublicKeyXYString(sm2PublicKeyX, sm2PublicKeyY).
        FromPrivateKeyString(sm2PrivateKeyD).
        CreatePrivateKey().
        ToKeyString()

    // =====

    // 检测私钥公钥是否匹配
    pri, _ := fs.Get(prifile)
    pub, _ := fs.Get(pubfile)

    res := cryptobin_sm2.New().
        FromPrivateKey([]byte(pri)).
        FromPublicKey([]byte(pub)).
        CheckKeyPair()

    fmt.Printf("check res: %#v", res)

}
~~~

* 【招商银行】支付签名验证
~~~go
package main

import (
    "fmt"
    "encoding/base64"

    cryptobin_sm2 "github.com/deatil/go-cryptobin/cryptobin/sm2"
)

func main() {
    // sm2 签名【招商银行】
    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, _ := base64.StdEncoding.DecodeString(sm2key)
    sm2data := `{"request":{"body":{"TEST":"中文","TEST2":"!@#$%^&*()","TEST3":12345,"TEST4":[{"arrItem1":"qaz","arrItem2":123,"arrItem3":true,"arrItem4":"中文"}],"buscod":"N02030"},"head":{"funcode":"DCLISMOD","userid":"N003261207"}},"signature":{"sigdat":"__signature_sigdat__"}}`
    sm2userid := "N0032612070000000000000000"
    sm2userid = sm2userid[0:16]
    sm2Sign := cryptobin_sm2.NewSM2().
        FromPrivateKeyBytes(sm2keyBytes).
        FromString(sm2data).
        SignHex([]byte(sm2userid)).
        ToBase64String()

    // sm2 验证【招商银行】
    sm2signdata := "CDAYcxm3jM+65XKtFNii0tKrTmEbfNdR/Q/BtuQFzm5+luEf2nAhkjYTS2ygPjodpuAkarsNqjIhCZ6+xD4WKA=="
    sm2Verify := cryptobin_sm2.NewSM2().
        FromBase64String(sm2signdata).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        VerifyHex([]byte(sm2data), []byte(sm2userid)).
        ToVerify()

    fmt.Println("签名结果：", sm2Sign)
    fmt.Println("验证结果：", sm2Verify)

}
~~~
