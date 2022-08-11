### 使用方法

* 对称加密使用
~~~go
package main

import (
    "fmt"

    cryptobin "github.com/deatil/go-cryptobin/cryptobin/crypto"
    "github.com/deatil/lakego-filesystem/filesystem"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 获取报错数据
    err := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12dfertf12dfertf12ty").
        TriDes().
        ECB().
        PKCS7Padding().
        Encrypt().
        Error().
        String()

    // 获取报错数据2
    var cypt2Err []error
    cypt2 := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        TriDes().
        CFB().
        PKCS7Padding().
        Encrypt().
        OnError(func(errs []error) {
            cypt2Err = errs
        }).
        ToBase64String()

    // =====

    // 加密
    cypt := cryptobin.
        FromString("useData").
        SetKey("dfertf12dfertf12").
        Aes().
        ECB().
        PKCS5Padding().
        Encrypt().
        ToBase64String()
    cyptde := cryptobin.
        FromBase64String("i3FhtTp5v6aPJx0wTbarwg==").
        SetKey("dfertf12dfertf12").
        Aes().
        ECB().
        PKCS5Padding().
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

    // Des-CBC 加密测试
    cypt2 := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12").
        SetIv("dfertf12").
        Des().
        CBC().
        PKCS7Padding().
        Encrypt().
        ToBase64String()
    cyptde2 := cryptobin.
        FromBase64String("W9LgNgPy/GBU635SnbdSgA==").
        SetKey("dfertf12").
        SetIv("dfertf12").
        Des().
        CBC().
        PKCS7Padding().
        Decrypt().
        ToString()

    // =====

    // TriDes-CFB 加密测试
    var cypt2Err []error
    var cypt2Err2 []error
    cypt2 := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        TriDes().
        CFB().
        PKCS7Padding().
        Encrypt().
        OnError(func(errs []error) {
            cypt2Err = errs
        }).
        ToBase64String()
    cyptde2 := cryptobin.
        FromBase64String("oCqlh4iTOp5+i5SVLN/KUw==").
        SetKey("dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        TriDes().
        CFB().
        PKCS7Padding().
        Decrypt().
        OnError(func(errs []error) {
            cypt2Err2 = errs
        }).
        ToString()

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

    // Xts 加密测试
    cypt1 := cryptobin.
        FromString("test-pass").
        SetKey("1234567890abcdef1234567890abcdef").
        Xts("Aes", 0x3333333333).
        PKCS5Padding().
        Encrypt().
        ToHexString()
    cyptde1 := cryptobin.
        FromHexString("d062ce7c53988c59acf6df73d148c2bf").
        SetKey("1234567890abcdef1234567890abcdef").
        PKCS5Padding().
        Xts("Aes", 0x3333333333).
        Decrypt().
        ToString()

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

}

~~~
