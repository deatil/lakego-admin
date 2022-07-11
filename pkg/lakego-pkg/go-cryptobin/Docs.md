### 使用方法

~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-cryptobin/cryptobin"
    "github.com/deatil/lakego-filesystem/filesystem"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 加密
    cypt := cryptobin.
        FromString("useData").
        SetKey("dfertf12dfertf12").
        Aes().
        ECB().
        PKCS7Padding().
        Encrypt().
        ToBase64String()
    cyptde := cryptobin.
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

    // =====

    // Des 加密测试
    cypt := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12").
        Des().
        ECB().
        PKCS7Padding().
        Encrypt().
        ToBase64String()
    cyptde := cryptobin.
        FromBase64String("bvifBivJ1GEJ0N/UiZry/A==").
        SetKey("dfertf12").
        Des().
        ECB().
        PKCS7Padding().
        Decrypt().
        ToString()

    // =====

    // TriDes 加密测试
    cypt := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12dfertf12dfertf12").
        TriDes().
        ECB().
        PKCS7Padding().
        Encrypt().
        ToHexString()
    cyptde := cryptobin.
        FromHexString("6ef89f062bc9d46109d0dfd4899af2fc").
        SetKey("dfertf12dfertf12dfertf12").
        TriDes().
        ECB().
        PKCS7Padding().
        Decrypt().
        ToString()

    // =====

    // RSA 加密测试
    enkey, _ := fs.Get("./config/key/encrypted-public.key")
    cypt := cryptobin.
        FromString("test-pass").
        SetKey(enkey).
        RsaEncrypt().
        ToBase64String()
    dekey, _ := fs.Get("./config/key/encrypted-private.key")
    cyptde := cryptobin.
        FromBase64String("AONrSI9z5rn8xWEbR9YfJSA6TRk5mlkuNrCPYqb/koEl63oS6Owhzaev2p1uHIwVV6L+k/dfOZNngIzRbCmf/UU4Fpp/gCxXzh2ZtB1x1Z7orQgUnJdiW9vKJKDGVyBR2znTzTNFD5UpJEOigr2T5VAEhVa4v8ZdxryI4Nlk8cvTSMVbDmz5tMK+2yPJsihsU1TOC8w8PxPPOPfDXDf72D2KrE7ayuCGI8iNVgPQuBkvL7N3t3RLoJzD2uiqcI7afuj59xK6RX/Q6eyrCYRcc1rJkNFSUmGuzzfwlSYYk4zgA+VCwDdhjbPy0Q5LTt3p5bR1FhaufP5SttsmCwTEMw==").
        SetKey(dekey).
        RsaDecrypt("testing").
        ToString()

    // =====

    // 获取报错数据
    err := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12dfertf12dfertf12ty").
        TriDes().
        ECB().
        PKCS7Padding().
        Encrypt().
        Error.
        Error()

    // =====

    // Rsa 生成证书
    rsa := cryptobin.NewRsa()
    rsaPriKey := rsa.
        GenerateKey(2048).
        CreatePKCS8WithPassword("123", "AES256CBC", "SHA256").
        ToKeyString()
    rsaPubKey := rsa.
        FromPKCS8WithPassword([]byte(rsaPriKey), "123").
        CreatePublicKey().
        ToKeyString()

    // =====

    // Ecdsa
    ecdsa := cryptobin.NewEcdsa()
    rsaPriKey := ecdsa.
        WithCurve("P521").
        GenerateKey().
        CreatePrivateKey().
        ToKeyString()
    rsaPubKey := ecdsa.
        FromPrivateKey([]byte(rsaPriKey)).
        WithCurve("P521").
        CreatePublicKey().
        ToKeyString()

    // =====

    // Ecdsa 验证
    pri, _ := fs.Get("./runtime/key/ec256-private.pem")
    pub, _ := fs.Get("./runtime/key/ec256-public.pem")
    ecdsa := cryptobin.NewEcdsa()
    rsaPriKey := ecdsa.
        FromPrivateKey([]byte(pri)).
        FromString("测试").
        Sign().
        ToBase64String()
    rsaPubKey := ecdsa.
        FromBase64String(rsaPriKey).
        FromPublicKey([]byte(pub)).
        Very([]byte("测试")).
        ToVeryed()

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
        PSSVery([]byte("测试")).
        ToVeryed()

    // =====

    // 生成 eddsa 证书
    eddsa := cryptobin.NewEdDSA().GenerateKey()
    eddsaPriKey := eddsa.
        CreatePrivateKey().
        ToKeyString()
    eddsaPubKey := eddsa.
        CreatePublicKey().
        ToKeyString()

    fs.Put("./runtime/key/eddsa_key", eddsaPriKey)
    fs.Put("./runtime/key/eddsa_key.pub", eddsaPubKey)

    // =====

    // eddsa 验证
    pri, _ := fs.Get("./runtime/key/eddsa_key")
    pub, _ := fs.Get("./runtime/key/eddsa_key.pub")
    rsa := cryptobin.NewEdDSA()
    rsaPriKey := rsa.
        FromPrivateKey([]byte(pri)).
        FromString("测试").
        Sign().
        ToBase64String()
    rsaPubKey := rsa.
        FromBase64String(rsaPriKey).
        FromPublicKey([]byte(pub)).
        Very([]byte("测试")).
        ToVeryed()

    // =====

    // Chacha20poly1305 加密测试
    cypt := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        Chacha20poly1305("werfrewerfre", "ftyhg5").
        Encrypt().
        ToBase64String()
    cyptde := cryptobin.
        FromBase64String("c2c0u6OYvU0EmsFapoCfiLky+OakQW9x/A==").
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        Chacha20poly1305("werfrewerfre", "ftyhg5").
        Decrypt().
        ToString()

    // =====

    // RC4 加密测试
    cypt := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12dfertf12dfertf12").
        RC4().
        Encrypt().
        ToHexString()
    cyptde := cryptobin.
        FromHexString("4308d5f24be9195317").
        SetKey("dfertf12dfertf12dfertf12").
        RC4().
        Decrypt().
        ToString()

    // =====

    // Chacha20 加密测试
    cypt := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12dfertf12dfertf12ghy6yhtg").
        Chacha20("fgr5tfgr5rtr").
        Encrypt().
        ToHexString()
    cyptde := cryptobin.
        FromHexString("a87757b7196994e818").
        SetKey("dfertf12dfertf12dfertf12ghy6yhtg").
        Chacha20("fgr5tfgr5rtr").
        Decrypt().
        ToString()

    // =====

    // SM4 加密测试
    cypt := cryptobin.
        FromString("test-pass").
        SetKey("1234567890abcdef").
        SM4().
        ECB().
        PKCS7Padding().
        Encrypt().
        ToHexString()
    cyptde := cryptobin.
        FromHexString("5d91a272c4ede4bf4cf19c963daec309").
        SetKey("1234567890abcdef").
        SM4().
        ECB().
        PKCS7Padding().
        Decrypt().
        ToString()

    // =====

    // Padding 加密测试
    cypt := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12").
        Des().
        ECB().
        TBCPadding().
        Encrypt().
        ToBase64String()
    cyptde := cryptobin.
        FromBase64String("bvifBivJ1GEXAEgBAo9OoA==").
        SetKey("dfertf12").
        Des().
        ECB().
        TBCPadding().
        Decrypt().
        ToString()

    // =====

    // SM2 生成证书
    sm2 := cryptobin.NewSM2()
    sm2PriKey := sm2.
        GenerateKey().
        CreatePrivateKeyWithPassword("123").
        ToKeyString()
    sm2PubKey := sm2.
        FromPrivateKeyWithPassword([]byte(sm2PriKey), "123").
        CreatePublicKey().
        ToKeyString()

    fs.Put("./runtime/key/sm2_en_key", sm2PriKey)
    fs.Put("./runtime/key/sm2_key.pub", sm2PubKey)

    // =====

    // SM2 加密
    sm2 := cryptobin.NewSM2()

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
    sm2 := cryptobin.NewSM2()

    enkey2, _ := fs.Get("./runtime/key/sm2_key.pub")
    sm2cypt := sm2.
        FromString("test-pass").
        FromPublicKey([]byte(enkey2)).
        Encrypt().
        ToBase64String()
    dekey2, _ := fs.Get("./runtime/key/sm2_key")
    sm2cyptde := sm2.
        FromBase64String("MHECIFVKOBAB9uiXrFQlNexfJuv7tjuydu7UdMYpTxQ/mPeHAiBSZdqNaciEP3XgX8xT2JLap4dWedX1EDQh7JyqifhHQAQgPcr5+KHIz3v300sGPc7nv6VM9fOo/kgPTHqZy5MtXMMECVKFT0dwWJwdCQ==").
        FromPrivateKey([]byte(dekey2)).
        Decrypt().
        ToString()

    // =====

    // SM2 验证
    sm2 := cryptobin.NewSM2()

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
        Very([]byte("test-pass")).
        ToVeryed()

    // =====

    // SM2 验证2
    sm2 := cryptobin.NewSM2()

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
        Very([]byte("test-pass")).
        ToVeryed()

    // =====

    // 国密 SM2 加密测试
    enkey, _ := fs.Get("./runtime/key/sm2_en_key.pub")
    cypt := cryptobin.
        FromString("test-pass").
        SetKey(enkey).
        SM2Encrypt().
        ToBase64String()
    dekey, _ := fs.Get("./runtime/key/sm2_en_key")
    cyptde := cryptobin.
        FromBase64String("MHECIELEZVMkhELFI5Anm+ReTOTvLErLhdVRthyfB0xgmfqSAiBeGAcCcqG04t+JFmQcpWhYnfS+y8V/LrD4pz5TNoZLWgQgHMMWWPA/puupOlcxpfuOxnauNA2K/dFOiFkW8m8A1vEECQrM2LIoXdHS0A==").
        SetKey(dekey).
        SM2Decrypt("123").
        ToString()

    // =====

    // SM2 生成 byte
    sm2 := cryptobin.NewSM2()

    dekey2, _ := fs.Get("./runtime/key/sm2_key")
    sm2PrivateKeyX := sm2.
        FromPrivateKey([]byte(dekey2)).
        GetPrivateKeyX().
        Bytes()
    sm2PrivateKeyY := sm2.
        FromPrivateKey([]byte(dekey2)).
        GetPrivateKeyY().
        Bytes()
    sm2PrivateKeyD := sm2.
        FromPrivateKey([]byte(dekey2)).
        GetPrivateKeyD().
        Bytes()

    x := cryptobin.NewEncoding().HexEncode(sm2a)
    y := cryptobin.NewEncoding().HexEncode(sm2b)
    d := cryptobin.NewEncoding().HexEncode(sm2c)

    // =====

    // SM2 加密2
    sm2PublicKeyX  := "a4b75c4c8c44d11687bdd93c0883e630c895234beb685910efbe27009ad911fa"
    sm2PublicKeyY  := "d521f5e8249de7a405f254a9888cbb8e651fd60c50bd22bd182a4bc7d1261c94"
    sm2PrivateKeyD := "0f495b5445eb59ddecf0626f5ca0041c550584f0189e89d95f8d4c52499ff838"

    sm2 := cryptobin.NewSM2()
    sm2PriKey := sm2.
        FromPublicKeyString(sm2PublicKeyX + sm2PublicKeyY).
        CreatePublicKey().
        ToKeyString()
    sm2PubKey := sm2.
        FromPublicKeyString(sm2PublicKeyX + sm2PublicKeyY).
        FromPrivateKeyString(sm2PrivateKeyD).
        CreatePrivateKey().
        ToKeyString()

    // =====

    // RsaOAEPEncrypt 加密测试
    enkey, _ := fs.Get("./runtime/key/sample_key.pub")
    cypt := cryptobin.
        FromString("test-pass").
        SetKey(enkey).
        RsaOAEPEncrypt("SHA1").
        ToBase64String()
    dekey, _ := fs.Get("./runtime/key/sample_key")
    cyptde := cryptobin.
        FromBase64String("W7k/gm81yoc2tAlV1vDM0HxMPRktqQ0OFScvhYgO8boc+jj/OY3CwFcNko98XQnKeNTzqctDtQb6QlRdBtCf76DMjhH/4un7FxuXnYF/D+GGbqV5M0P/Sfqr4zqt7jPXiUqV3LUmASoWc8TnA70XY/ZWZ35ZwEBMYfJcmxdJpT8XfW0i0HSZpFNg/bZ55o/fy7+8bVcXPiVdTtvncLIUxxZsWZbLG4K4ufZ476efi8N36CPOOvUHigiVTTHWznk4U/Bd1RlBgxCOQNbhQUco3LcBzSxiKyQLqC+jQ7GMzw1EBWB3p9RHez5xVPX51GyOJJHmFLeLNuIOEtGWPB7yZQ==").
        SetKey(dekey).
        RsaOAEPDecrypt("SHA1").
        ToString()

    // =====

    // sm2 签名【招行】
    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes := encoding.FromBase64String(sm2key).ToBytes()
    sm2data := `{"request":{"body":{"TEST":"中文","TEST2":"!@#$%^&*()","TEST3":12345,"TEST4":[{"arrItem1":"qaz","arrItem2":123,"arrItem3":true,"arrItem4":"中文"}],"buscod":"N02030"},"head":{"funcode":"DCLISMOD","userid":"N003261207"}},"signature":{"sigdat":"__signature_sigdat__"}}`
    sm2userid := "N0032612070000000000000000"
    sm2userid = sm2userid[0:16]
    sm2Sign := cryptobin.NewSM2().
        FromPrivateKeyBytes(sm2keyBytes).
        FromString(sm2data).
        SignHex([]byte(sm2userid)).
        ToBase64String()

    // =====

    // sm2 验证【招行】
    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes := encoding.FromBase64String(sm2key).ToBytes()
    sm2data := `{"request":{"body":{"TEST":"中文","TEST2":"!@#$%^&*()","TEST3":12345,"TEST4":[{"arrItem1":"qaz","arrItem2":123,"arrItem3":true,"arrItem4":"中文"}],"buscod":"N02030"},"head":{"funcode":"DCLISMOD","userid":"N003261207"}},"signature":{"sigdat":"__signature_sigdat__"}}`
    sm2userid := "N0032612070000000000000000"
    sm2userid = sm2userid[0:16]

    sm2signdata := "CDAYcxm3jM+65XKtFNii0tKrTmEbfNdR/Q/BtuQFzm5+luEf2nAhkjYTS2ygPjodpuAkarsNqjIhCZ6+xD4WKA=="
    sm2Sign := cryptobin.NewSM2().
        FromPrivateKeyBytes(sm2keyBytes).
        FromBase64String(sm2signdata).
        VerifyHex([]byte(sm2data), []byte(sm2userid)).
        ToVeryed()

}

~~~
