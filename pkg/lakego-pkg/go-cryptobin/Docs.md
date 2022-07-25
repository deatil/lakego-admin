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

    // Rsa 生成证书2
    rsa22 := cryptobin.NewRsa().GenerateKey(2048)
    rsaPriKey22 := rsa22.
        CreatePKCS1().
        ToKeyString()
    rsaPubKey22 := rsa22.
        CreatePublicKey().
        ToKeyString()

    // =====

    // Rsa 加密解密 - 公钥加密/私钥解密
    rsa := cryptobin.NewRsa()

    enkey, _ := fs.Get("./runtime/key/rsa_key.pub")
    cypt := rsa.
        FromString("test-pass").
        FromPublicKey([]byte(enkey)).
        Encrypt().
        ToBase64String()
    dekey, _ := fs.Get("./runtime/key/rsa_key")
    cyptde := rsa.
        FromBase64String("MHECIFVKOBAB9uiXrFQlNexfJuv7tjuydu7UdMYpTxQ/mPeHAiBSZdqNaciEP3XgX8xT2JLap4dWedX1EDQh7JyqifhHQAQgPcr5+KHIz3v300sGPc7nv6VM9fOo/kgPTHqZy5MtXMMECVKFT0dwWJwdCQ==").
        FromPrivateKey([]byte(dekey)).
        Decrypt().
        ToString()

    // =====

    // RSA 加密测试2
    rsaPfx := encoding.Base64Decode("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")
    rsa2 := cryptobin.NewRsa().FromPKCS12WithPassword([]byte(rsaPfx), "")

    var rsa2Err error
    rsa2cypt := rsa2.
        OnError(func(err error) {
            rsa2Err = err
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
        FromPublicKey([]byte(dekey)).
        PubKeyDecrypt().
        ToString()

    // =====

    // Ecdsa
    ecdsa := cryptobin.NewEcdsa()
    ecdsaPriKey := ecdsa.
        WithCurve("P521").
        GenerateKey().
        CreatePrivateKey().
        ToKeyString()
    ecdsaPubKey := ecdsa.
        FromPrivateKey([]byte(ecdsaPriKey)).
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

    // ca 证书生成
    caSubj := &cryptobin.CAPkixName{
        CommonName:    "github.com",
        Organization:  []string{"Company, INC."},
        Country:       []string{"US"},
        Province:      []string{""},
        Locality:      []string{"San Francisco"},
        StreetAddress: []string{"Golden Gate Bridge"},
        PostalCode:    []string{"94016"},
    }
    ca := cryptobin.NewCA().GenerateRsaKey(4096)
    ca1KeyString := ca.CreatePrivateKey().ToKeyString()

    // ca
    ca1 := ca.MakeCA(caSubj, 1, "SHA256WithRSA")
    ca1String := ca1.CreateCA().ToKeyString()

    // tls
    ca1Csr := ca1.GetCert()
    ca2 := ca.MakeCert(caSubj, 1, []string{"test.default.svc", "test"}, []net.IP{}, "SHA256WithRSA")
    ca2String := ca2.CreateCert(ca1Csr).ToKeyString()

    // fs.Put("./runtime/key/ca.cst", ca1String)
    // fs.Put("./runtime/key/ca.key", ca1KeyString)
    // fs.Put("./runtime/key/ca_tls.cst", ca2String)
    // fs.Put("./runtime/key/ca_tls.key", ca2KeyString)

    // =====

    // sm2 pkcs12 证书生成
    caSubj := &cryptobin.CAPkixName{
        CommonName:    "github.com",
        Organization:  []string{"Company, INC."},
        Country:       []string{"US"},
        Province:      []string{""},
        Locality:      []string{"San Francisco"},
        StreetAddress: []string{"Golden Gate Bridge"},
        PostalCode:    []string{"94016"},
    }
    ca := cryptobin.NewCA().GenerateSM2Key()
    cert := ca.MakeSM2Cert(caSubj, 1, []string{"test.default.svc", "test"}, []net.IP{}, "SM2WithSHA1")

    pkcs12Data := cert.CreatePKCS12(nil, "123456").ToKeyString()

    // fs.Put("./runtime/key/ec-pkcs12.pfx", pkcs12Data)

    // =====

    // sm2 pkcs12 证书生成2
    str := "MIICiTCCAi6gAwIBAgIIICAEFwACVjAwCgYIKoEcz1UBg3UwdjEcMBoGA1UEAwwTU21hcnRDQV9UZXN0X1NNMl9DQTEVMBMGA1UECwwMU21hcnRDQV9UZXN0MRAwDgYDVQQKDAdTbWFydENBMQ8wDQYDVQQHDAbljZfkuqwxDzANBgNVBAgMBuaxn+iLjzELMAkGA1UEBhMCQ04wHhcNMjAwNDE3MDYwNjA4WhcNMTkwOTAzMDE1MzE5WjCBrjFGMEQGA1UELQw9YXBpX2NhX1RFU1RfVE9fUEhfUkFfVE9OR0pJX2FlNTA3MGNiY2E4NTQyYzliYmJmOTRmZjcwNThkNmEzMTELMAkGA1UEBhMCQ04xDTALBgNVBAgMBG51bGwxDTALBgNVBAcMBG51bGwxFTATBgNVBAoMDENGQ0FTTTJBR0VOVDENMAsGA1UECwwEbnVsbDETMBEGA1UEAwwKY2hlbnh1QDEwNDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAWeikXULbz1RqgmVzJWtSDMa3f9wirzwnceb1WIWxTqJaY+3xNlsM63oaIKJCD6pZu14EDkLS0FTP1uX3EySOajbTBrMAsGA1UdDwQEAwIGwDAdBgNVHQ4EFgQUbMrrNQDS1B1yjyrkgq2FWGi5zRcwHwYDVR0jBBgwFoAUXPO6JYzCZQzsZ+++3Y1rp16v46wwDAYDVR0TBAUwAwEB/zAOBggqgRzQFAQBAQQCBQAwCgYIKoEcz1UBg3UDSQAwRgIhAMcbwSDvL78qDSoqQh/019EEk4UNHP7zko0t1GueffTnAiEAupHr3k4vWSWV1SEqds+q8u4CbRuuRDvBOQ6od8vGzjM="
    decodeString := encoding.Base64Decode(str)
    x, _ := x509.ParseCertificate([]byte(decodeString))

    ca := cryptobin.NewCA().GenerateSM2Key()
    ca = ca.WithCert(x)

    pkcs12Data := ca.CreatePKCS12(nil, "123456").ToKeyString()

    // fs.Put("./runtime/key/ec-pkcs12.pfx", pkcs12Data)

    // =====

    // pkcs12 证书生成2
    caSubj := &cryptobin.CAPkixName{
        CommonName:    "github.com",
        Organization:  []string{"Company, INC."},
        Country:       []string{"US"},
        Province:      []string{""},
        Locality:      []string{"San Francisco"},
        StreetAddress: []string{"Golden Gate Bridge"},
        PostalCode:    []string{"94016"},
    }
    ca := cryptobin.NewCA().GenerateEcdsaKey("P256")
    cert := ca.MakeCert(caSubj, 1, []string{"test.default.svc", "test"}, []net.IP{}, "ECDSAWithSHA256")

    pkcs12Data := cert.CreatePKCS12(nil, "123456").ToKeyString()

    fs.Put("./runtime/key/ec-pkcs12.pfx", pkcs12Data)

    // =====

    // pkcs12 证书解析
    pfxData, _ := fs.Get("./runtime/key/sm2-pkcs12.pfx")
    ca := cryptobin.NewCA().FromSM2PKCS12OneCert([]byte(pfxData), "123456")
    pkcs12PrivData := ca.CreatePrivateKey().ToKeyString()

    // =====

    // DSA 生成证书
    dsa := cryptobin.NewDSA()
    dsaPriKey := dsa.
        GenerateKey("L2048N256").
        CreatePrivateKey().
        ToKeyString()
    dsaPubKey := dsa.
        FromPrivateKey([]byte(dsaPriKey)).
        CreatePublicKey().
        ToKeyString()
    // fs.Put("./runtime/key/dsa", dsaPriKey)
    // fs.Put("./runtime/key/dsa.pub", dsaPubKey)

    // DSA 验证
    dsa := cryptobin.NewDSA()

    dsaPri, _ := fs.Get("./runtime/key/dsa")
    dsacypt := dsa.
        FromString("test-pass").
        FromPrivateKey([]byte(dsaPri)).
        Sign().
        ToBase64String()
    dsaPub, _ := fs.Get("./runtime/key/dsa.pub")
    dsacyptde := dsa.
        FromBase64String("MjkzNzYzMDE1NjgzNDExMTM0ODE1MzgxOTAxMDIxNzQ0Nzg3NTc3NTAxNTU2MDIwNzg4OTc1MzY4Mzc0OTE5NzcyOTg3NjI1MTc2OTErNDgzNDU3NDAyMzYyODAzMDM3MzE1NjE1NDk1NDEzOTQ4MDQ3NDQ3ODA0MDE4NDY5NDA1OTA3ODExNjM1Mzk3MDEzOTY4MTM5NDg2NDc=").
        FromPublicKey([]byte(dsaPub)).
        Very([]byte("test-pass")).
        ToVeryed()

}

~~~
