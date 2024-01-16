### Rsa 使用说明 / RSA Docs

`EncryptECB`, `PrivateKeyEncryptECB`, `EncryptOAEPECB` 为 `JAVA` 对应的 `ECB` 模式，可加密大数据
`EncryptECB`, `PrivateKeyEncryptECB`, `EncryptOAEPECB`  for `JAVA` `ECB` mode and can encrypt big data


* 包引入 / import pkg
~~~go
import (
    "github.com/deatil/go-cryptobin/cryptobin/rsa"
)
~~~

* 数据输入方式 / input funcs
`FromBytes(data []byte)`, `FromString(data string)`, `FromBase64String(data string)`, `FromHexString(data string)`

* 数据输出方式 / output funcs
`ToBytes()`, `ToString()`, `ToBase64String()`, `ToHexString()`, 

* 获取 error / get error
`Error()`

* 生成证书 / make keys
~~~go
func main() {
    // bits = 512 | 1024 | 2048 | 4096
    obj := rsa.New().
        GenerateKey(2048)
        // GenerateMultiPrimeKey(nprimes int, bits int)

    // 生成私钥
    // create private key
    var PriKeyPem string = obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        // CreatePKCS1PrivateKey().
        // CreatePKCS1PrivateKeyWithPassword("123", "AES256CBC").
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256").
        // CreateXMLPrivateKey().
        ToKeyString()

    // 自定义私钥加密类型
    // use custom encrypt options
    var PriKeyPem string = obj.
        CreatePKCS8PrivateKeyWithPassword("123", rsa.Opts{
            Cipher:  rsa.GetCipherFromName("AES256CBC"),
            KDFOpts: rsa.ScryptOpts{
                CostParameter:            1 << 15,
                BlockSize:                8,
                ParallelizationParameter: 1,
                SaltSize:                 8,
            },
        }).
        ToKeyString()

    // 生成公钥
    // create public key
    var PubKeyPem string = obj.
        CreatePKCS1PublicKey().
        // CreatePKCS8PublicKey().
        // CreateXMLPublicKey().
        ToKeyString()
}
~~~

* 签名验证 / sign data
~~~go
func main() {
    obj := rsa.New()
    
    // 待签名数据
    // no sign data
    var data string = "..."
    
    // 签名数据
    // sign data
    var sigBase64String string = "..."

    // 私钥签名
    // private key sign data
    var priKeyPem string = ""
    sigBase64String = obj.
        FromString(data).
        FromPrivateKey([]byte(priKeyPem)).
        // FromPrivateKeyWithPassword([]byte(priKeyPem), "123").
        // FromPKCS1PrivateKey([]byte(priKeyPem)).
        // FromPKCS1PrivateKeyWithPassword([]byte(priKeyPem), "123").
        // FromPKCS8PrivateKey([]byte(priKeyPem)).
        // FromPKCS8PrivateKeyWithPassword([]byte(priKeyPem), "123").
        // FromXMLPrivateKey([]byte(priKeyXML)).
        SetSignHash("SHA256").
        Sign().
        // SignPSS().
        ToBase64String()
        
    // 公钥验证
    // public key verify signed data
    var pubKeyPem string = ""
    var res bool = obj.
        FromBase64String(sigBase64String).
        FromPublicKey([]byte(pubKeyPem)).
        // FromPKCS1PublicKey([]byte(pubKeyPem)).
        // FromPKCS8PublicKey([]byte(pubKeyPem)).
        // FromXMLPublicKey([]byte(pubKeyXML)).
        SetSignHash("SHA256").
        Verify([]byte(data)).
        // VerifyPSS([]byte(data)).
        ToVerify()
}
~~~

* 加密解密 - 公钥加密/私钥解密 / Encrypt with public key
~~~go
func main() {
    obj := rsa.New()
    
    // 待加密数据
    // no sign data
    var data string = "..."

    // 公钥加密
    // public key Encrypt data
    var pubKeyPem string = ""
    var enData string = obj.
        FromString(data).
        FromPublicKey([]byte(pubKeyPem)).
        // FromPKCS1PublicKey([]byte(pubKeyPem)).
        // FromPKCS8PublicKey([]byte(pubKeyPem)).
        // FromXMLPublicKey([]byte(pubKeyXML)).
        Encrypt().
        // EncryptOAEP("SHA1")
        ToBase64String()

    // 私钥解密
    // private key Decrypt data
    var priKeyPem string = ""
    var deData string = obj.
        FromBase64String(enData).
        FromPrivateKey([]byte(priKeyPem)).
        // FromPrivateKeyWithPassword([]byte(priKeyPem), "123").
        // FromPKCS1PrivateKey([]byte(priKeyPem)).
        // FromPKCS1PrivateKeyWithPassword([]byte(priKeyPem), "123").
        // FromPKCS8PrivateKey([]byte(priKeyPem)).
        // FromPKCS8PrivateKeyWithPassword([]byte(priKeyPem), "123").
        // FromXMLPrivateKey([]byte(priKeyXML)).
        Decrypt().
        // DecryptOAEP("SHA1")
        ToString()
}
~~~

* 加密解密 - 私钥加密/公钥解密 / Encrypt with private key
~~~go
func main() {
    obj := rsa.New()
    
    // 待加密数据
    // no sign data
    var data string = "..."

    // 私钥加密
    // private key Decrypt data
    var priKeyPem string = ""
    var enData string = obj.
        FromString(data).
        FromPrivateKey([]byte(priKeyPem)).
        // FromPrivateKeyWithPassword([]byte(priKeyPem), "123").
        // FromPKCS1PrivateKey([]byte(priKeyPem)).
        // FromPKCS1PrivateKeyWithPassword([]byte(priKeyPem), "123").
        // FromPKCS8PrivateKey([]byte(priKeyPem)).
        // FromPKCS8PrivateKeyWithPassword([]byte(priKeyPem), "123").
        // FromXMLPrivateKey([]byte(priKeyXML)).
        PrivateKeyEncrypt().
        ToBase64String()

    // 公钥解密
    // public key Encrypt data
    var pubKeyPem string = ""
    var deData string = obj.
        FromBase64String(enData).
        FromPublicKey([]byte(pubKeyPem)).
        // FromPKCS1PublicKey([]byte(pubKeyPem)).
        // FromPKCS8PublicKey([]byte(pubKeyPem)).
        // FromXMLPublicKey([]byte(pubKeyXML)).
        PublicKeyDecrypt().
        ToString()
}
~~~

* 检测私钥公钥是否匹配 / Check KeyPair
~~~go
func main() {
    var prikeyPem string = "..."
    var pubkeyPem string = "..."

    var res bool = rsa.New().
        // FromPrivateKey([]byte(prikeyPem)).
        // FromPrivateKeyWithPassword([]byte(prikeyPem), "123").
        // FromPKCS1PrivateKey([]byte(prikeyPem)).
        // FromPKCS1PrivateKeyWithPassword([]byte(prikeyPem), "123").
        FromPKCS8PrivateKey([]byte(prikeyPem)).
        // FromPKCS8PrivateKeyWithPassword([]byte(prikeyPem), "123").
        // FromPublicKey([]byte(pubkeyPem)).
        // FromPKCS1PublicKey([]byte(pubkeyPem)).
        FromPKCS8PublicKey([]byte(pubkeyPem)).
        CheckKeyPair()
}
~~~
